// Routing convenience only. The server remains the strict document validator
// and authorization authority; source text is never serialized for submission.
export const kinds=Object.freeze(['groups','contract-registry','execution-rules','compliance','approvers','platform']);

export function argumentsFor(argv,allowed) {
  const options={},positional=[];
  for(let i=0;i<argv.length;i++) {
    const value=argv[i];
    if(!value.startsWith('--')) {positional.push(value);continue;}
    const key=value.slice(2);
    if(!allowed.includes(key)||options[key]!==undefined||!argv[i+1]||argv[i+1].startsWith('--'))throw Error(`Invalid or repeated option ${value}`);
    options[key]=argv[++i];
  }
  return {options,positional};
}

export function explicitSelection(options={},env=process.env) {
  const choose=(flag,variable)=>{
    if(options[flag]!==undefined&&env[variable]!==undefined&&options[flag]!==env[variable])throw Error(`${flag} conflicts with ${variable}`);
    return options[flag]??env[variable];
  };
  return {kind:choose('kind','OPS_CONFIGURATION_KIND'),orgId:choose('org','OPS_ORG_ID')};
}

function selection(kind,scope,explicit) {
  if(!kinds.includes(kind))throw Error('Select a supported configuration kind explicitly or declare it in source');
  if(explicit.kind!==undefined&&explicit.kind!==kind)throw Error('Selected kind conflicts with source or prepared metadata');
  if(!scope||typeof scope!=='object'||Array.isArray(scope))throw Error('Configuration scope is required');
  if(kind==='platform') {
    if(scope.kind!=='platform'||(scope.id!==undefined&&scope.id!=='')||explicit.orgId!==undefined)throw Error('Platform scope has no organization ID; unset OPS_ORG_ID / --org');
    return {kind,scope:{kind:'platform'}};
  }
  if(scope.kind!=='organization'||typeof scope.id!=='string'||!scope.id.trim()||scope.id!==scope.id.trim())throw Error('Organization scope requires its declared ID');
  if(explicit.orgId!==undefined&&explicit.orgId!==scope.id)throw Error('Selected organization conflicts with source or prepared metadata');
  return {kind,scope:{kind:'organization',id:scope.id}};
}

// JSON.parse alone loses duplicate keys. Walk its valid JSON token stream to
// reject duplicate/case-variant routing metadata, including escaped key names.
// Unrelated source keys are left untouched for the server's strict parser.
function routingDocument(source,strictDuplicates=false) {
  const document=JSON.parse(source);
  if(!document||typeof document!=='object'||Array.isArray(document))throw Error('Configuration source must be an object');
  const tokens=source.match(/"(?:\\.|[^"\\])*"|[{}\[\]:,]|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g);
  let cursor=0;
  const walk=path=>{
    const token=tokens[cursor++];
    if(token==='{') {
      const seen=new Set();
      if(tokens[cursor]==='}') {cursor++;return;}
      do {
        const key=JSON.parse(tokens[cursor++]);cursor++; // key and colon
        const routing=path.length===0?['kind','scope']:path.length===1&&path[0]==='scope'?['kind','id']:[];
        const folded=key.toLowerCase();
        if(strictDuplicates||routing.includes(folded)) {
          if((routing.includes(folded)&&key!==folded)||seen.has(folded))throw Error('Duplicate or ambiguous routing metadata');
          seen.add(folded);
        }
        walk([...path,key]);
      } while(tokens[cursor++]===',');
    } else if(token==='[') {
      if(tokens[cursor]===']') {cursor++;return;}
      let index=0;
      do {walk([...path,index++]);} while(tokens[cursor++]===',');
    }
  };
  walk([]);
  return document;
}

export function sourceSelection(source,explicit={}) {
  const document=routingDocument(source);
  return selection(document.kind,document.scope,explicit);
}
export function selectedContext(explicit={}) {
  return selection(explicit.kind,explicit.kind==='platform'?{kind:'platform'}:{kind:'organization',id:explicit.orgId},explicit);
}
export function preparedSelection(prepared,explicit={}) {
  if(!prepared?.selection||typeof prepared.draft?.id!=='string'||!prepared.draft.id||!Array.isArray(prepared.coactivate)||!prepared.coactivate.every(id=>typeof id==='string'&&id))throw Error('Invalid prepared result metadata');
  return selection(prepared.selection.kind,prepared.selection.scope,explicit);
}
export function parsePreparedResult(source) {return routingDocument(source,true);}
export function organization(selected) {return selected.scope.id??'';}

export function executionCapabilities(context) {return context?.capabilities?.executionPolicy;}
export function requireExecutionSupport(capabilities,action) {
  if(capabilities?.configuredConsumer!=='guarded-reth'||capabilities?.[action]!==true)throw Error(`Execution action unavailable: ${capabilities?.unavailableReason??'execution_capability_unavailable'}`);
}
export function checkReviewSelection(reviewed,selected) {
  const revisions=reviewed.review.revisions??[];
  for(const revision of revisions) {
    if(revision.scope?.kind!==selected.scope.kind||(revision.scope?.id??'')!==(selected.scope.id??''))throw Error('Fresh review scope does not match selected scope');
  }
  if(!revisions.some(revision=>revision.id===reviewed.revisionId&&revision.kind===selected.kind))throw Error('Fresh review kind does not match selected kind');
}
export function requireActivation(context,reviewed) {
  if((reviewed.review.revisions??[]).some(revision=>revision.kind==='execution-rules'))requireExecutionSupport(executionCapabilities(context),'activationSupported');
}
export function checkPreparedReview(prepared,reviewed) {
  const old=prepared.candidateDigests,newDigests=reviewed.candidateDigests;
  if(!old||typeof old!=='object'||Object.keys(old).length!==Object.keys(newDigests).length||Object.entries(newDigests).some(([kind,digest])=>old[kind]!==digest))throw Error('Fresh review differs from prepared candidate digests');
  const oldIDs=prepared.review?.revisions?.map(revision=>revision.id).sort();
  const newIDs=reviewed.review.revisions?.map(revision=>revision.id).sort();
  if(!oldIDs||JSON.stringify(oldIDs)!==JSON.stringify(newIDs))throw Error('Fresh review differs from prepared revision IDs');
}
