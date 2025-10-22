var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// .wrangler/tmp/bundle-7Fmk26/strip-cf-connecting-ip-header.js
function stripCfConnectingIPHeader(input, init) {
  const request = new Request(input, init);
  request.headers.delete("CF-Connecting-IP");
  return request;
}
__name(stripCfConnectingIPHeader, "stripCfConnectingIPHeader");
globalThis.fetch = new Proxy(globalThis.fetch, {
  apply(target, thisArg, argArray) {
    return Reflect.apply(target, thisArg, [
      stripCfConnectingIPHeader.apply(null, argArray)
    ]);
  }
});

// src/index.ts
var src_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/_health") {
      return new Response("ok", { status: 200 });
    }
    const upgradeHeader = request.headers.get("Upgrade");
    if (url.pathname === "/boards" && upgradeHeader === "websocket") {
      const boardId = url.searchParams.get("boardId");
      if (!boardId) {
        return new Response(JSON.stringify({ error: "boardId query param required" }), {
          status: 400,
          headers: { "content-type": "application/json" }
        });
      }
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      attachBoardSocket(server, boardId, ctx);
      return new Response(null, {
        status: 101,
        webSocket: client
      });
    }
    return new Response("Not Found", { status: 404 });
  }
};
function attachBoardSocket(socket, boardId, ctx) {
  socket.accept();
  const keepAlive = setInterval(() => {
    try {
      socket.send(
        JSON.stringify({
          type: "keepalive",
          boardId,
          timestamp: Date.now()
        })
      );
    } catch (error) {
      console.warn("[board-room] keepalive failed", error);
      clearInterval(keepAlive);
    }
  }, 3e4);
  const shutdown = /* @__PURE__ */ __name(() => {
    clearInterval(keepAlive);
  }, "shutdown");
  socket.addEventListener("close", shutdown);
  socket.addEventListener("error", shutdown);
  socket.send(
    JSON.stringify({
      type: "ack",
      boardId,
      timestamp: Date.now()
    })
  );
  socket.addEventListener("message", (event) => {
    try {
      const payload = typeof event.data === "string" ? JSON.parse(event.data) : event.data;
      if (payload?.type === "ping") {
        socket.send(
          JSON.stringify({
            type: "pong",
            boardId,
            timestamp: Date.now()
          })
        );
        return;
      }
      socket.send(
        JSON.stringify({
          type: "event",
          boardId,
          echo: payload,
          timestamp: Date.now()
        })
      );
    } catch (error) {
      console.warn("[board-room] message parse failed", error);
      socket.send(
        JSON.stringify({
          type: "error",
          boardId,
          message: "Unable to parse payload"
        })
      );
    }
  });
  ctx.waitUntil(
    new Promise((resolve) => {
      socket.addEventListener("close", () => resolve(), { once: true });
    })
  );
}
__name(attachBoardSocket, "attachBoardSocket");
var BoardRoomDO = class {
  constructor(state) {
    this.state = state;
    this.state.blockConcurrencyWhile(async () => {
      const initialized = await this.state.storage.get("initialized");
      if (!initialized) {
        await this.state.storage.put("initialized", true);
      }
    });
  }
  async fetch(request) {
    const url = new URL(request.url);
    return new Response(
      JSON.stringify({ status: "BoardRoomDO stub", id: this.state.id.toString(), pathname: url.pathname }),
      { status: 200, headers: { "content-type": "application/json" } }
    );
  }
};
__name(BoardRoomDO, "BoardRoomDO");

// ../node_modules/.pnpm/wrangler@3.114.15_@cloudflare+workers-types@4.20251014.0/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../node_modules/.pnpm/wrangler@3.114.15_@cloudflare+workers-types@4.20251014.0/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-7Fmk26/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = src_default;

// ../node_modules/.pnpm/wrangler@3.114.15_@cloudflare+workers-types@4.20251014.0/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-7Fmk26/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof __Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
__name(__Facade_ScheduledController__, "__Facade_ScheduledController__");
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = (request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    };
    #dispatcher = (type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    };
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  BoardRoomDO,
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
