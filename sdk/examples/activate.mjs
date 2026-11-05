import {readFile} from 'node:fs/promises';
import {clientFromEnvironment} from './session.mjs';
import {argumentsFor,explicitSelection,selectedContext,preparedSelection,parsePreparedResult,organization,executionCapabilities,checkReviewSelection,checkPreparedReview,requireActivation} from './configuration.mjs';

// Explicit, separate invocation using an independent approver's named session,
// or a service session and a manifest from its trusted external approval system.
const {options,positional}=argumentsFor(process.argv.slice(2),['kind','org','prepared']);
if(positional.length>(options.prepared?1:2)||(!options.prepared&&!positional[0]))throw Error('Usage: node examples/activate.mjs --kind KIND [--org ID] REVISION_ID [SIGNED_CI_APPROVAL.json], or --prepared REVIEW.json [SIGNED_CI_APPROVAL.json]');
const prepared=options.prepared?parsePreparedResult(await readFile(options.prepared,'utf8')):undefined;
const explicit=explicitSelection(options);
const selected=prepared?preparedSelection(prepared,explicit):selectedContext(explicit);
const id=prepared?.draft.id??positional[0];
const client=await clientFromEnvironment();
const {kind}=selected,orgId=organization(selected);
const siblings=(process.env.OPS_COACTIVATE??'').split(',').filter(Boolean);
if(prepared&&process.env.OPS_COACTIVATE!==undefined&&JSON.stringify(siblings)!==JSON.stringify(prepared.coactivate))throw Error('OPS_COACTIVATE conflicts with prepared revision IDs');
const context=await client.context(orgId,kind);
const reviewed=await client.reviewDraft(orgId,kind,id,prepared?.coactivate??siblings);
checkReviewSelection(reviewed,selected);
if(prepared)checkPreparedReview(prepared,reviewed);
process.stderr.write(`${JSON.stringify({selection:selected,executionPolicy:executionCapabilities(context)})}\n`);
requireActivation(context,reviewed);
const approvalFile=positional[options.prepared?0:1];
const result=approvalFile
  ?await client.activateWithCI(reviewed,JSON.parse(await readFile(approvalFile,'utf8')))
  :await client.activateReviewed(reviewed);
process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
