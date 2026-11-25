import Module from 'node:module';
import test from 'node:test';
import assert from 'node:assert/strict';
import type { AgentClient, AgentMethod } from './agentClient';
import { AgentClientError } from './agentClient';
import type { ProjectContext } from './projectContext';

type RegisteredCommand = () => unknown;
type ModuleLoader = (request: string, parent: NodeJS.Module | null, isMain: boolean) => unknown;
const registered = new Map<string, RegisteredCommand>();
const project: ProjectContext = { root:'/workspace/demo/nested', projectId:'lk_proj_actual', defaultProfileId:'lk_prof_actual', profileName:'staging', storePath:'/local/store.db', cliPath:'/trusted/bin/locket', projectName:'demo' };
const inputs: string[]=[];
const prompts: string[]=[];
const maskedInputs: boolean[]=[];
const errors: string[]=[];
const infos: string[]=[];
const terminals: Array<Record<string,unknown>>=[];
let trusted=true;
let pick='deploy';
let terminalShown=false;
let terminalError: Error | undefined;
class Disposable {
  public constructor(private readonly disposeFn:()=>void=()=>undefined) {}
  public dispose():void {this.disposeFn();}
}
const vscodeStub={
  commands:{registerCommand:(id:string,callback:RegisteredCommand)=>{registered.set(id,callback);return new Disposable(()=>registered.delete(id));}},
  workspace:{get isTrusted(){return trusted;},workspaceFolders:[{name:'demo',uri:{fsPath:'/workspace/demo'}}]},
  window:{
    showInputBox:async (options:{prompt?:string;password?:boolean})=>{
      prompts.push(options.prompt??'');
      maskedInputs.push(options.password === true);
      return inputs.shift();
    },
    showQuickPick:async <T extends {label:string}>(items:readonly T[])=>items.find(item=>item.label===pick),
    showInformationMessage:async(message:string)=>{infos.push(message);return undefined;},
    showWarningMessage:async(message:string)=>{errors.push(message);return undefined;},
    showErrorMessage:async(message:string)=>{errors.push(message);return undefined;},
    createTerminal:(options:Record<string,unknown>)=>{
      if (terminalError !== undefined) { throw terminalError; }
      terminals.push(options);
      return {show:()=>{terminalShown=true;}};
    },
    createWebviewPanel:()=>({dispose:()=>undefined,onDidDispose:()=>undefined,webview:{html:''}}),
  },
  env:{clipboard:{writeText:async()=>undefined,readText:async()=>''}},
  ViewColumn:{Active:1},Disposable,
};
const loader=Module as unknown as {_load:ModuleLoader};
const originalLoad=loader._load;
loader._load=function(request,parent,isMain):unknown {return request==='vscode'?vscodeStub:originalLoad.call(this,request,parent,isMain);};
let register: (client:AgentClient,deps?:{resolveProject:()=>Promise<ProjectContext|undefined>})=>Disposable;
test.before(async()=>{register=(await import('./commands.js')).registerLocketCommands as unknown as typeof register;});
test.after(()=>{loader._load=originalLoad;});
test.beforeEach(()=>{
  registered.clear();
  for (const entries of [inputs, prompts, maskedInputs, errors, infos, terminals]) { entries.length = 0; }
  trusted = true;
  pick = 'deploy';
  terminalShown = false;
  terminalError = undefined;
});
function client(invoke:(method:AgentMethod,payload:unknown)=>Promise<unknown>):AgentClient {return {invoke,status:async()=>({project_id:'wrong-stale-project'})} as unknown as AgentClient;}
async function command(
  id: string,
  agent: AgentClient,
  resolveProject: () => Promise<ProjectContext | undefined> = async () => project,
): Promise<void> {
  const disposable = register(agent, { resolveProject });
  try {
    const callback = registered.get(id);
    assert.ok(callback, `missing command ${id}`);
    await callback();
  } finally {
    disposable.dispose();
  }
  assert.equal(registered.size, 0);
}

test('run policy executes the trusted CLI in an interactive terminal using real resolved project',async()=>{
  const calls:Array<{method:AgentMethod;payload:unknown}>=[];
  await command('locket.runPolicy',client(async(method,payload)=>{calls.push({method,payload});return {rows:[{id:'p1',name:'deploy',command_kind:'argv',command_preview:'npm run deploy'}]};}));
  assert.deepEqual(calls,[{method:'ListPolicies',payload:{project_id:project.projectId,privacy_redact_names:false}}]);
  assert.deepEqual(terminals,[{name:'Locket: deploy',shellPath:project.cliPath,shellArgs:['run','deploy'],cwd:project.root}]);
  assert.equal(terminalShown,true);
  assert.deepEqual(prompts,[]);
});

test('unlock infers project/store/profile IDs and only prompts for passphrase if needed',async()=>{
  const calls:unknown[]=[];
  await command('locket.unlock',client(async(method,payload)=>{calls.push({method,payload});return {};}));
  assert.deepEqual(calls,[{method:'Unlock',payload:{project_id:project.projectId,passphrase:null,ttl_seconds:1800,audit:{store_path:project.storePath,profile_id:project.defaultProfileId}}}]);
  assert.deepEqual(prompts,[]);
});

test('reveal opens fixed CLI terminal without requesting or capturing plaintext through the extension',async()=>{
  inputs.push('DATABASE_URL');
  const calls:unknown[]=[];
  await command('locket.revealSecret',client(async(method,payload)=>{calls.push({method,payload});return {value:'must-not-be-read',ttl_seconds:1};}));
  assert.deepEqual(calls,[]);
  assert.deepEqual(prompts,['Secret name']);
  assert.deepEqual(terminals,[{name:'Locket Reveal approval: DATABASE_URL',shellPath:project.cliPath,shellArgs:['get','--reveal','--','DATABASE_URL'],cwd:project.root}]);
  assert.equal(terminalShown,true);
  assert.match(infos[0]??'',/terminal/iu);
  assert.match(infos[0]??'',/staging/u);
});

test('copy opens fixed CLI clipboard route without claiming the value was copied',async()=>{
  inputs.push('API_KEY');
  const calls:unknown[]=[];
  await command('locket.copySecret',client(async(method,payload)=>{calls.push({method,payload});return {};}));
  assert.deepEqual(calls,[]);
  assert.deepEqual(prompts,['Secret name']);
  assert.deepEqual(terminals,[{name:'Locket Copy approval: API_KEY',shellPath:project.cliPath,shellArgs:['get','--copy','--','API_KEY'],cwd:project.root}]);
  assert.equal(terminalShown,true);
  assert.equal(infos.some(message=>/copied|success/iu.test(message)),false);
});

for(const invalid of ['', '   ', '--help', 'lowercase', 'API_KEY;touch file', 'A\nB']) {
  test(`value action refuses nonportable secret input ${JSON.stringify(invalid)}`,async()=>{
    inputs.push(invalid);
    let calls=0;
    await command('locket.copySecret',client(async()=>{calls++;return {};}));
    assert.equal(calls,0);
    assert.equal(terminals.length,0);
    assert.equal(infos.length,0);
    assert.equal(errors.length,1);
  });
}

test('profile switch infers paths and retries dangerous-profile rejection with typed confirmation',async()=>{
  inputs.push('prod','prod');
  const calls:Array<{method:AgentMethod;payload:unknown}>=[];
  await command('locket.switchProfile',client(async(method,payload)=>{calls.push({method,payload});if(calls.length===1)throw AgentClientError.agent({error:'ConfirmationFailed',message:'confirmation did not match',retryable:false});return {};}));
  assert.equal(calls.length,2);
  const base={config_path:`${project.root}/locket.toml`,store_path:project.storePath,project_id:project.projectId,profile_name:'prod',privacy_redact_names:false};
  assert.deepEqual(calls[0],{method:'SetActiveProfile',payload:base});
  assert.deepEqual(calls[1],{method:'SetActiveProfile',payload:{...base,confirmation:'prod'}});
  assert.equal(prompts.length,2);
});

test('audit infers store and project metadata without path prompts',async()=>{
  const calls:unknown[]=[];
  await command('locket.openAuditView',client(async(method,payload)=>{calls.push({method,payload});return {rows:[],chain_status:{hmac_ok:null,first_break_sequence:null,rows_verified:0,locked:true}};}));
  assert.deepEqual(calls,[{method:'ListAudit',payload:{store_path:project.storePath,project_id:project.projectId,limit:200,redact_names:false}}]);
  assert.deepEqual(prompts,[]);
});

test('scan runs the trusted CLI with known-value coverage instead of the empty RPC compatibility handler',async()=>{
  let calls=0;
  await command('locket.scanWorkspace',client(async()=>{calls++;return {findings:[],locked:true};}));
  assert.equal(calls,0);
  assert.deepEqual(terminals,[{name:'Locket Scan',shellPath:project.cliPath,shellArgs:['scan','--require-known'],cwd:project.root}]);
  assert.equal(terminalShown,true);
  assert.equal(infos.some(message=>/completed|no findings/iu.test(message)),false);
});

test('scan cannot launch from an untrusted workspace or missing project',async()=>{
  let resolutions=0;
  const disposable=register(client(async()=>{throw new Error('unexpected RPC');}),{resolveProject:async()=>{resolutions++;return undefined;}});
  try {
    trusted=false;
    await registered.get('locket.scanWorkspace')?.();
    assert.equal(resolutions,0);
    trusted=true;
    await registered.get('locket.scanWorkspace')?.();
    assert.equal(resolutions,1);
    assert.deepEqual(terminals,[]);
    assert.deepEqual(infos,[]);
  } finally { disposable.dispose(); }
});

test('untrusted workspace never resolves or invokes a process-backed action',async()=>{
  trusted=false;
  let resolutions=0;
  let calls=0;
  const disposable=register(client(async()=>{calls++;return {};}),{resolveProject:async()=>{resolutions++;return project;}});
  try{await registered.get('locket.runPolicy')?.();}finally{disposable.dispose();}
  assert.equal(resolutions,0);assert.equal(calls,0);assert.equal(terminals.length,0);
});

test('lock sends the desktop source and only announces success on acknowledgement', async () => {
  const calls: unknown[] = [];
  await command('locket.lock', client(async (method, payload) => { calls.push({ method, payload }); }));
  assert.deepEqual(calls, [{ method: 'Lock', payload: { source: 'desktop' } }]);
  assert.deepEqual(infos, ['Locket vault is locked.']);

  await command('locket.lock', client(async () => { throw AgentClientError.protocol('invalid lock response'); }));
  assert.deepEqual(errors, ['Locket agent protocol error: invalid lock response']);
  assert.equal(infos.length, 1);
});

test('unlock uses a masked prompt and surfaces a failed retry', async () => {
  const passphrases: unknown[] = [];
  inputs.push('fixture passphrase');
  await command('locket.unlock', client(async (_, payload) => {
    passphrases.push((payload as { passphrase: unknown }).passphrase);
    throw AgentClientError.agent({ error: 'UnlockRequired', message: 'unlock required', retryable: true });
  }));
  assert.deepEqual(maskedInputs, [true]);
  assert.deepEqual(passphrases, [null, 'fixture passphrase']);
  assert.deepEqual(errors, ['passphrase did not authenticate']);
});

test('open project commands stop when selection is cancelled', async () => {
  const agent = client(async () => assert.fail('unexpected RPC'));
  for (const id of ['revealSecret', 'unlock', 'switchProfile', 'runPolicy', 'scanWorkspace', 'openAuditView']) {
    await command(`locket.${id}`, agent, async () => undefined);
  }
  assert.deepEqual([prompts, infos, errors, terminals], [[], [], [], []]);
});

test('project resolver failures surface through the command without attempting an RPC', async () => {
  const agent = client(async () => assert.fail('unexpected RPC'));
  await command('locket.revealSecret', agent, async () => { throw new Error('project unavailable'); });
  await command('locket.revealSecret', agent, async () => { throw undefined; });
  assert.deepEqual(errors, ['project unavailable', 'Locket project metadata is unavailable.']);
  assert.deepEqual(prompts, []);
});

test('cancelling secret and profile prompts leaves project state untouched', async () => {
  const agent = client(async () => assert.fail('unexpected RPC'));
  await command('locket.revealSecret', agent);
  await command('locket.switchProfile', agent);
  assert.deepEqual(prompts, ['Secret name', 'Profile name']);
  assert.deepEqual([infos, errors, terminals], [[], [], []]);
});

test('invalid profile and audit inputs are reported before any agent request', async () => {
  const agent = client(async () => assert.fail('unexpected RPC'));
  inputs.push(' ');
  await command('locket.switchProfile', agent);
  await command('locket.openAuditView', agent, async () => ({ ...project, storePath: '' }));
  assert.deepEqual(errors, ['profile name is required', 'store path is required']);
});

for (const confirmation of [undefined, 'staging']) {
  test(`dangerous profile switch stops on ${confirmation === undefined ? 'cancelled' : 'mismatched'} confirmation`, async () => {
    let calls = 0;
    inputs.push('prod');
    if (confirmation !== undefined) { inputs.push(confirmation); }
    await command('locket.switchProfile', client(async () => {
      calls += 1;
      throw AgentClientError.agent({ error: 'ConfirmationFailed', message: 'confirmation required', retryable: false });
    }));
    assert.equal(calls, 1);
    assert.deepEqual(infos, []);
    assert.deepEqual(errors, confirmation === undefined ? [] : ['Profile confirmation did not match.']);
  });
}

test('profile, policy, and audit commands report RPC errors without success messages', async () => {
  const agent = client(async () => { throw AgentClientError.protocol('invalid response'); });
  inputs.push('dev');
  for (const id of ['switchProfile', 'runPolicy', 'openAuditView']) {
    await command(`locket.${id}`, agent);
  }
  assert.deepEqual(errors, Array(3).fill('Locket agent protocol error: invalid response'));
  assert.deepEqual([infos, terminals], [[], []]);
});

test('policy command handles invalid metadata, an empty list, a dismissed picker, and an option-like name', async () => {
  await command('locket.runPolicy', client(async () => assert.fail('unexpected RPC')),
    async () => ({ ...project, projectId: '' }));
  await command('locket.runPolicy', client(async () => ({ rows: [] })));
  const agent = client(async () => ({
    rows: [{ id: 'p1', name: '--help', command_kind: 'argv', command_preview: 'echo hello' }],
  }));
  await command('locket.runPolicy', agent);
  pick = '--help';
  await command('locket.runPolicy', agent);
  assert.deepEqual(infos, ['Locket has no saved command policies for this project.']);
  assert.deepEqual(errors, ['This policy name cannot be launched from the editor.']);
  assert.deepEqual(terminals, []);
});

test('terminal creation failure is reported for a workspace scan', async () => {
  terminalError = new Error('terminal unavailable');
  await command('locket.scanWorkspace', client(async () => assert.fail('unexpected RPC')));
  assert.deepEqual(errors, ['Locket command failed.']);
  assert.deepEqual(infos, []);
  assert.equal(terminalShown, false);
});
