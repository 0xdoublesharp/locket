// Use the client transform with the in-memory Vue host so V8 measures the
// same template code the component tests run.
export default {
  name: 'vue-renderer',
  viteEnvironment: 'client',
  setup() {
    // Vue's v-model checks these constructors when an input is updated.
    Object.assign(globalThis, { Document: class {}, ShadowRoot: class {} });
    return { teardown() {} };
  },
};
