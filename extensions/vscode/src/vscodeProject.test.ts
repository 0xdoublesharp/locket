import Module from 'node:module';
import test from 'node:test';
import assert from 'node:assert/strict';
import * as helpers from './projectContext';

type ModuleLoader=(request:string,parent:NodeJS.Module|null,isMain:boolean)=>unknown;
let trusted=true;
let editor: {document:{uri:{scheme:string;fsPath:string}}}|undefined;
let terminal: {shellIntegration?:{cwd:{scheme:string;fsPath:string}};creationOptions:object}|undefined;
let picks=0;
let pickedRoot: string | undefined;
const observed:helpers.ResolveProjectOptions[]=[];
const folders=[{name:'one',uri:{fsPath:'/workspace/one'}},{name:'two',uri:{fsPath:'/workspace/two'}}];
let workspaceFolders: typeof folders | undefined;
const stub={workspace:{get isTrusted(){return trusted;},get workspaceFolders(){return workspaceFolders;}},window:{
  get activeTextEditor(){return editor;},get activeTerminal(){return terminal;},
  showQuickPick:async<T extends {root:string}>(items:readonly T[])=>{picks++;return items.find(item=>item.root===pickedRoot);},
}};
const loader=Module as unknown as {_load:ModuleLoader};
const original=loader._load;
loader._load=function(request,parent,isMain):unknown {
  if(request==='vscode')return stub;
  if(request==='./projectContext')return {...helpers,resolveProjectContext:async(options:helpers.ResolveProjectOptions)=>{observed.push(options);return {root:options.cwd,projectId:'real-project',defaultProfileId:'real-profile',profileName:'dev',projectName:'fixture',cliPath:'/trusted/locket',storePath:'/local/store.db'};}};
  return original.call(this,request,parent,isMain);
};
let adapter:typeof import('./vscodeProject');
test.before(async()=>{adapter=await import('./vscodeProject.js');});
test.after(()=>{loader._load=original;});
test.beforeEach(()=>{
  trusted = true;
  editor = undefined;
  terminal = undefined;
  picks = 0;
  pickedRoot = '/workspace/two';
  workspaceFolders = folders;
  observed.length = 0;
});

test('active nested editor directory resolves project through CLI without choosing the first workspace',async()=>{
  editor={document:{uri:{scheme:'file',fsPath:'/workspace/two/nested/src/main.ts'}}};
  await adapter.resolveActiveProjectContext();
  assert.equal(observed[0]?.cwd,'/workspace/two/nested/src');assert.equal(picks,0);
});
test('active terminal shell-integration cwd resolves nested project',async()=>{
  terminal={shellIntegration:{cwd:{scheme:'file',fsPath:'/workspace/one/nested'}},creationOptions:{}};
  await adapter.resolveActiveProjectContext();
  assert.equal(observed[0]?.cwd,'/workspace/one/nested');assert.equal(picks,0);
});
test('multi-root workspace asks only when editor and terminal do not identify a folder',async()=>{
  await adapter.resolveActiveProjectContext();
  assert.equal(picks,1);assert.equal(observed[0]?.cwd,'/workspace/two');
});
test('background terminal without cwd cannot inherit first-workspace context',async()=>{
  assert.equal(await adapter.resolveProjectForCwd(undefined),undefined);
  assert.equal(observed.length,0);assert.equal(picks,0);
});
test('untrusted workspace is rejected before CLI metadata resolution',async()=>{
  trusted=false;
  await assert.rejects(adapter.resolveActiveProjectContext(),/trusted/iu);
  assert.equal(observed.length,0);assert.equal(picks,0);
});

test('a single workspace is the default when the active file is outside it', async () => {
  workspaceFolders = folders.slice(0, 1);
  editor = { document: { uri: { scheme: 'file', fsPath: '/workspace/one-sibling/main.ts' } } };
  assert.equal((await adapter.resolveActiveProjectContext())?.root, '/workspace/one');
  assert.equal(picks, 0);
  assert.equal(await adapter.resolveProjectForCwd('/workspace/one-sibling'), undefined);
  assert.equal(observed.length, 1);
});

test('empty and cancelled workspaces never invoke project resolution', async () => {
  workspaceFolders = undefined;
  await assert.rejects(adapter.resolveActiveProjectContext(), /Open a project folder/u);
  assert.equal(await adapter.resolveProjectForCwd('/workspace/two'), undefined);
  assert.equal(picks, 0);

  workspaceFolders = folders;
  pickedRoot = undefined;
  assert.equal(await adapter.resolveActiveProjectContext(), undefined);
  assert.equal(picks, 1);
  assert.deepEqual(observed, []);
});

test('terminal uses a filesystem creation cwd when shell integration has no local path', () => {
  const directory = '/workspace/one/nested';
  const fileUri = { scheme: 'file', fsPath: directory };
  const remoteUri = { scheme: 'vscode-remote', fsPath: '/remote/path' };
  type Terminal = NonNullable<Parameters<typeof adapter.workingDirectoryForTerminal>[0]>;
  assert.equal(adapter.workingDirectoryForTerminal({
    shellIntegration: { cwd: remoteUri }, creationOptions: { cwd: directory },
  } as unknown as Terminal), directory);
  assert.equal(adapter.workingDirectoryForTerminal({
    creationOptions: { cwd: fileUri },
  } as unknown as Terminal), directory);
  assert.equal(adapter.workingDirectoryForTerminal({
    creationOptions: { cwd: remoteUri },
  } as unknown as Terminal), undefined);
});
