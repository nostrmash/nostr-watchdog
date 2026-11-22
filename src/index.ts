import { defaultDependencies } from "./deps";
import { handleFetch, handleScheduled } from "./http/app";

export default {
  fetch(request, env) {
    return handleFetch(request, env, defaultDependencies());
  },
  scheduled(controller, env, ctx) {
    ctx.waitUntil(handleScheduled(controller, env, defaultDependencies()));
  },
} satisfies ExportedHandler<Env>;
