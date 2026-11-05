import {readFile} from 'node:fs/promises';
import {clientFromEnvironment} from './session.mjs';
import {argumentsFor,explicitSelection,sourceSelection,selectedContext,organization,executionCapabilities,requireExecutionSupport,checkReviewSelection} from './configuration.mjs';

const {options,positional}=argumentsFor(process.argv.slice(2),['kind','org']);
if(positional.length>1)throw Error('Usage: node examples/prepare.mjs [--kind KIND] [--org ID] [SOURCE.json]');
const source=positional[0]?new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await readFile(positional[0])):undefined;
const explicit=explicitSelection(options);
const selected=source===undefined?selectedContext(explicit):sourceSelection(source,explicit);
const client=await clientFromEnvironment();
const {kind}=selected,orgId=organization(selected);
const context=await client.context(orgId,kind);
if(source===undefined) {
  // Export the complete editable source. Edit a copy and pass its path to
  // this command. Server context contains migration diagnostics separately.
  process.stdout.write(`${JSON.stringify(context,null,2)}\n`);
} else {
  let request;
  if(process.env.OPS_PREVIEW_FILE) {
    if(kind!=='execution-rules')throw Error('Node preview requires an execution-rules candidate');
    requireExecutionSupport(executionCapabilities(context),'nodePreviewSupported');
    request=JSON.parse(await readFile(process.env.OPS_PREVIEW_FILE,'utf8'));
    if(request.dryRun||request.principalId)throw Error('Author example previews only its own ordinary execution');
  }
  const draft=await client.submitDraft(orgId,kind,source);
  if(!draft.id)throw Error('Server returned a draft without a revision ID');
  const siblings=(process.env.OPS_COACTIVATE??'').split(',').filter(Boolean);
  const reviewed=await client.reviewDraft(orgId,kind,draft.id,siblings);
  checkReviewSelection(reviewed,selected);
  let preview;
  if(request)preview=await client.preview(orgId,{...request,candidateRevisionId:draft.id});
  process.stdout.write(`${JSON.stringify({selection:selected,coactivate:reviewed.coactivate,draft,review:reviewed.review,candidateDigests:reviewed.candidateDigests,executionPolicy:executionCapabilities(context),preview},null,2)}\n`);
  if(reviewed.review.revisions?.some(revision=>revision.kind==='execution-rules')&&executionCapabilities(context)?.activationSupported!==true)process.stderr.write('Execution activation unavailable: this deployment has no supported execution consumer. Candidate evidence is retained.\n');
  process.stderr.write('Draft prepared. Independent human review or trusted CI approval is required for activation.\n');
}
