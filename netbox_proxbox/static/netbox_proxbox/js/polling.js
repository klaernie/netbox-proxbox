import { getCsrfToken } from "./common.js";
import { populateTable } from "./table.js";

const WEBSOCKET_ROUTE = "/plugins/proxbox/websocket";
const NEXT_CURSOR_HEADER = "X-Proxbox-Next-Cursor";
const CURSOR_RESET_HEADER = "X-Proxbox-Cursor-Reset";
const CURSOR_GAP_HEADER = "X-Proxbox-Cursor-Gap";
const CURSOR_PATTERN = /^[0-9a-f]{16}\.\d{1,18}$/;
const RUN_ID_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;
const RUN_MODE_OBJECT = "sync-run";
const POLL_INTERVAL_MS = 1000;
// Stop after this many consecutive empty polls with no terminal message.
const DEFAULT_MAX_IDLE_POLLS = 120;

// Backend message ``object`` whose ``end: true`` completes each legacy sync.
// A run-correlated full update instead completes on its aggregate terminal.
const TERMINAL_OBJECT = {
    "full-update": "virtual_machine",
    devices: "device",
    "virtual-machines": "virtual_machine",
};

const ACTIVE_RUN_IDS = new Map();

const TABLES = {
    virtual_machine: {
        tableType: "virtual_machine",
        tableDivId: "virtual-machines-div",
        tableId: "virtual-machine-table-data",
        defaultRowId: "virtual-machines-table-default-td",
    },
    device: {
        tableType: "device",
        tableDivId: "device-div",
        tableId: "device-table-data",
        defaultRowId: "device-table-default-td",
    },
};

function syncUrl(objectType) {
    return `${WEBSOCKET_ROUTE}/${encodeURIComponent(objectType)}`;
}

async function readJson(response) {
    try {
        return await response.json();
    } catch (error) {
        return null;
    }
}

/**
 * Ask the server-side WebSocket bridge to start one sync kind.
 *
 * Starting a sync is a state change, so it is a CSRF-protected POST. The
 * server answers with the message cursor at the time the sync was queued;
 * pass it to ``poll`` so only messages produced after the trigger are read.
 * A 409 means a sync of this kind is already running; its cursor is still
 * returned so the caller can follow it.
 */
export async function startSync(objectType) {
    const response = await fetch(syncUrl(objectType), {
        method: "POST",
        credentials: "same-origin",
        headers: {
            Accept: "application/json",
            "X-CSRFToken": getCsrfToken(),
        },
    });
    const payload = (await readJson(response)) || {};
    if (!response.ok && response.status !== 409) {
        throw new Error(payload.error || `Sync request failed with status ${response.status}`);
    }
    if (RUN_ID_PATTERN.test(payload.run_id || "")) {
        ACTIVE_RUN_IDS.set(objectType, payload.run_id);
    } else {
        ACTIVE_RUN_IDS.delete(objectType);
    }
    return payload;
}

function parseMessage(rawMessage) {
    if (typeof rawMessage !== "string") {
        return rawMessage;
    }
    try {
        return JSON.parse(rawMessage);
    } catch (error) {
        return null;
    }
}

function renderMessage(message) {
    const table = message ? TABLES[message.object] : undefined;
    if (table) {
        populateTable({ ...table, jsonMessage: message });
    }
}

function endsObject(message, object) {
    return Boolean(message && message.end === true && message.object === object);
}

async function fetchPage(objectType, cursor) {
    const params = new URLSearchParams({ json_response: "true" });
    if (cursor) {
        params.set("after", cursor);
    }
    const response = await fetch(`${syncUrl(objectType)}?${params.toString()}`, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
    });
    const data = await readJson(response);
    if (!response.ok || !Array.isArray(data)) {
        throw new Error(`Polling failed with status ${response.status}`);
    }
    if (response.headers.get(CURSOR_RESET_HEADER) || response.headers.get(CURSOR_GAP_HEADER)) {
        // Another worker answered, or messages were evicted: earlier progress
        // and terminals cannot be attributed to this run.
        throw new Error("The sync message stream was interrupted; reload the page to see the current state.");
    }
    const headerCursor = response.headers.get(NEXT_CURSOR_HEADER);
    return { data, cursor: CURSOR_PATTERN.test(headerCursor || "") ? headerCursor : cursor };
}

function selectedRunId(objectType, callbacks) {
    const candidate = callbacks.runId ?? callbacks.run_id ?? ACTIVE_RUN_IDS.get(objectType);
    return RUN_ID_PATTERN.test(candidate || "") ? candidate : null;
}

function hasRunId(message) {
    return message && Object.prototype.hasOwnProperty.call(message, "run_id");
}

function isProtocolMessageValid(message) {
    if (!message || (hasRunId(message) && !RUN_ID_PATTERN.test(message.run_id || ""))) {
        return false;
    }
    if (message.object === "full-update" && message.end === true) {
        return message.status === "completed" || message.status === "failed";
    }
    return true;
}

function messagesForRun(messages, runId) {
    if (!runId) {
        return {
            messages: messages.filter((message) => message && !hasRunId(message)),
            runId: null,
        };
    }
    const downgradeIndex = messages.findIndex((message) => (
        message
        && message.object === RUN_MODE_OBJECT
        && message.run_id === runId
        && message.correlated === false
    ));
    if (downgradeIndex < 0) {
        return {
            messages: messages.filter((message) => message && message.run_id === runId),
            runId,
        };
    }
    const correlated = messages
        .slice(0, downgradeIndex)
        .filter((message) => message && message.run_id === runId);
    const legacy = messages.slice(downgradeIndex + 1).filter((message) => (
        message && !hasRunId(message)
    ));
    return { messages: [...correlated, ...legacy], runId: null };
}

function completionMessage(objectType, messages, runId) {
    const terminalObject = runId && objectType === "full-update"
        ? "full-update"
        : TERMINAL_OBJECT[objectType];
    return messages.find((message) => {
        if (!endsObject(message, terminalObject)) {
            return false;
        }
        if (!runId || objectType !== "full-update") {
            return true;
        }
        return message.status === "completed" || message.status === "failed";
    });
}

function failedFullUpdateError(message) {
    const failedStages = Object.entries(message.stages || {})
        .filter(([, status]) => status === "failed")
        .map(([stage]) => stage);
    const suffix = failedStages.length ? `: ${failedStages.join(", ")}` : "";
    return new Error(`Full update failed${suffix}.`);
}

function failedRunMessage(messages) {
    return messages.find((message) => (
        message.object === RUN_MODE_OBJECT
        && message.end === true
        && message.status === "failed"
    ));
}

/**
 * Follow buffered backend messages with a per-client cursor.
 *
 * GET never starts a sync and never removes messages for other users. Empty
 * polls are normal while the backend works; polling completes only on the
 * terminal message for ``objectType``. A correlated run ignores every frame
 * without its exact run id and waits for the aggregate full-update terminal.
 * A cursor reset or gap is reported as an error, and polling gives up with a
 * timeout after ``maxIdlePolls`` consecutive empty polls.
 */
export async function poll(objectType, callbacks = {}) {
    const { onComplete = () => {}, onError = () => {}, cursor = null } = callbacks;
    const maxIdlePolls = callbacks.maxIdlePolls ?? DEFAULT_MAX_IDLE_POLLS;
    let runId = selectedRunId(objectType, callbacks);
    let nextCursor = cursor;
    let idlePolls = 0;

    while (idlePolls < maxIdlePolls) {
        let page;
        try {
            page = await fetchPage(objectType, nextCursor);
        } catch (error) {
            console.error("Polling failed:", error);
            onError(error);
            return;
        }
        nextCursor = page.cursor;
        const messages = page.data.map(parseMessage).filter(isProtocolMessageValid);
        const selected = messagesForRun(messages, runId);
        if (runId && !selected.runId) {
            ACTIVE_RUN_IDS.delete(objectType);
        }
        runId = selected.runId;
        const runMessages = selected.messages;
        idlePolls = runMessages.length === 0 ? idlePolls + 1 : 0;
        runMessages.forEach(renderMessage);
        const runFailure = failedRunMessage(runMessages);
        if (runFailure) {
            ACTIVE_RUN_IDS.delete(objectType);
            onError(new Error(runFailure.error || "The sync connection is no longer trusted."));
            return;
        }
        const terminal = completionMessage(objectType, runMessages, runId);
        if (terminal && runId && objectType === "full-update" && terminal.status === "failed") {
            ACTIVE_RUN_IDS.delete(objectType);
            onError(failedFullUpdateError(terminal));
            return;
        }
        if (terminal) {
            ACTIVE_RUN_IDS.delete(objectType);
            onComplete();
            return;
        }
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
    onError(new Error("Timed out waiting for the sync to finish."));
}
