// Read-only assertions against the response which caused the actual render.
// Independent CURRENT observations and returned page lengths are never totals.
import assert from 'node:assert/strict';
import path from 'node:path';

const quantity = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,77})$/.test(value) && BigInt(value) < (1n << 256n);
const formatted = value => BigInt(value).toLocaleString('en-US');
function units(value, decimals) {
  if (value === undefined) return 'Unavailable';
  if (value === null) return 'Hidden';
  assert.ok(quantity(value)); assert.ok(Number.isInteger(decimals) && decimals >= 0 && decimals <= 255);
  if (!decimals) return formatted(value);
  const padded = value.padStart(decimals + 1, '0'), tail = padded.slice(-decimals).replace(/0+$/, '');
  return formatted(padded.slice(0, -decimals)) + (tail ? '.' + tail : '');
}
async function renderedResponse(page, origin, endpoint, action, query = () => true) {
  const started = Date.now(), requests = new WeakSet();
  const observe = request => requests.add(request);
  page.on('request', observe);
  try {
    const [response] = await Promise.all([page.waitForResponse(response => {
      const request = response.request(), url = new URL(response.url());
      return requests.has(request) && request.timing().startTime >= started && url.origin === origin && url.pathname === '/api/v2/explorer' + endpoint && request.method() === 'GET' && query(url.searchParams);
    }, { timeout: 35_000 }), action()]);
    assert.equal(response.status(), 200, 'Authorized page read ' + endpoint);
    return response.json();
  } finally { page.off('request', observe); }
}

function countText(count) {
  assert.ok(count && typeof count === 'object' && !Array.isArray(count), 'Native count metadata required');
  assert.equal(count.population, 'ORDINARY_VISIBLE_ROWS');
  assert.ok(['SNAPSHOT', 'CURRENT'].includes(count.consistency));
  assert.ok(['current', 'complete_range', 'scan_limited', 'history_pruned', 'index_floor'].includes(count.coverage));
  assert.ok(Object.keys(count).every(key => ['status', 'value', 'lowerBound', 'population', 'consistency', 'observedAt', 'range', 'coverage'].includes(key)));
  if (count.observedAt !== undefined) { assert.match(count.observedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/); assert.ok(Number.isFinite(Date.parse(count.observedAt))); }
  if (count.status === 'unavailable') assert.ok(!Object.hasOwn(count, 'value') && !Object.hasOwn(count, 'lowerBound'), 'Unavailable is never zero');
  else {
    assert.match(count.observedAt ?? '', /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/);
    assert.ok(Number.isFinite(Date.parse(count.observedAt)), 'Successful count has an actual observation');
    if (count.status === 'exact') { assert.ok(quantity(count.value)); assert.ok(!Object.hasOwn(count, 'lowerBound')); }
    else { assert.equal(count.status, 'at_least'); assert.ok(quantity(count.lowerBound)); assert.ok(!Object.hasOwn(count, 'value')); assert.equal(count.consistency, 'SNAPSHOT'); }
  }
  if (count.consistency === 'CURRENT') { assert.equal(count.coverage, 'current'); assert.equal(count.range, undefined); }
  else if (count.status !== 'unavailable') {
    assert.ok(count.range && quantity(count.range.fromBlock) && quantity(count.range.throughBlock));
    assert.ok(BigInt(count.range.fromBlock) <= BigInt(count.range.throughBlock)); assert.match(count.range.headHash, /^0x[0-9a-f]{64}$/);
    assert.ok(count.status === 'exact' ? ['complete_range', 'history_pruned', 'index_floor'].includes(count.coverage) : ['scan_limited', 'history_pruned', 'index_floor'].includes(count.coverage), 'Historical count preserves its explicitly bounded retained coverage');
  }
  return count.status === 'unavailable' ? '—' : (count.status === 'at_least' ? '≥' : '') + formatted(count.value ?? count.lowerBound);
}
async function renderedCount(cell, count, label, interact = false) {
  const text = countText(count), span = cell.locator('button[aria-label][title]').first();
  await span.waitFor(); assert.equal(await span.textContent(), text, label + ': exact string formatting');
  const note = await span.getAttribute('title'); assert.equal(await span.getAttribute('aria-label'), note);
  if (count.status === 'unavailable') {
    assert.match(note, /unavailable/i); if (count.observedAt === undefined) assert.ok(!note.includes('Observed '), label + ': no invented time');
  } else {
    assert.ok(note.includes('Observed ' + count.observedAt), label + ': time belongs to this response');
    if (count.consistency === 'CURRENT') assert.ok(note.includes('Current indexed values.'));
    else assert.ok(note.includes(`Retained blocks ${count.range.fromBlock}–${count.range.throughBlock}.`));
    if (count.coverage === 'scan_limited') assert.ok(note.includes('safety limit'));
    if (count.coverage === 'history_pruned') assert.ok(note.includes('pruned'));
    if (count.coverage === 'index_floor') assert.ok(note.includes('not been indexed'));
  }
  if (interact) {
    const page = cell.page();
    await span.focus(); await span.click();
    const tooltip = page.getByRole('tooltip'); await tooltip.waitFor();
    assert.equal((await tooltip.textContent()).trim(), note.slice(text.length + 2), label + ': focus/tap opens real coverage text');
    const popup = page.locator('[data-radix-popper-content-wrapper]').filter({ has: tooltip });
    const bounds = await popup.boundingBox();
    assert.ok(bounds && bounds.x >= 0 && bounds.x + bounds.width <= page.viewportSize().width + 1, label + ': tooltip fits viewport');
    await page.keyboard.press('Escape'); await tooltip.waitFor({ state: 'hidden' });
  }
}
function blockCount(block) {
  const metric=block.counts?.transactions,text=countText(metric);
  assert.equal(metric.consistency,'SNAPSHOT');
  if(metric.range){assert.equal(metric.range.fromBlock,block.number);assert.equal(metric.range.throughBlock,block.number);assert.equal(metric.range.headHash,block.hash);}
  if(metric.status==='unavailable')assert.equal(metric.observedAt,undefined);
  else assert.notEqual(block.source,'NODE','Node-only header never supplies a numeric historical count');
  exactFlatFields(block,{transactionCount:'transactions'});
  return {text,scope:`Ordinary transactions in block ${block.number}.`,metric};
}
function blockCountObservationMatches(block,rendered) {
  const expected=blockCount(block),note=rendered.title;
  if(rendered.count!==expected.text||typeof note!=='string'||!note.includes(expected.scope))return false;
  const metric=expected.metric;
  if(metric.status==='unavailable')return !note.includes('Observed ')&&/unavailable/i.test(note)&&(metric.coverage!=='history_pruned'||note.includes('has been pruned'))&&(metric.coverage!=='index_floor'||note.includes('has not been indexed'))&&(metric.coverage!=='scan_limited'||note.includes('read’s limits'));
  return note.includes(`Observed ${metric.observedAt}.`)&&note.includes(`Retained blocks ${metric.range.fromBlock}–${metric.range.throughBlock}.`)&&(metric.coverage!=='history_pruned'||note.includes('has been pruned'))&&(metric.coverage!=='index_floor'||note.includes('has not been indexed'))&&(metric.coverage!=='scan_limited'||note.includes('safety limit'));
}
async function renderedBlockCount(cell,block,label,interact=false) {
  const expected=blockCount(block);
  await renderedCount(cell,expected.metric,label,interact);
  const button=cell.getByRole('button');
  assert.ok(blockCountObservationMatches(block,{count:await button.textContent(),title:await button.getAttribute('title')}),label+': selected-block scope, range and observation belong to this response');
  return expected;
}
async function blockCountSurfaces(page,runtime,name) {
  const list=await renderedResponse(page,runtime.explorerOrigin,'/blocks',()=>page.goto(runtime.explorerOrigin+'/blocks'),query=>query.get('limit')==='25');
  await page.getByRole('heading',{name:'Blocks',exact:true}).waitFor();
  let exact=0;
  for(const block of list.items){const row=page.getByTestId('block-row').filter({has:page.locator(`a[href="/block/${block.number}"]`)}),cell=row.locator('td').nth(2);await row.waitFor();const expected=await renderedBlockCount(cell,block,name+' block list');if(expected.metric.status==='exact')exact++;}
  assert.ok(exact>0,name+': known block-authorized list proves an actual exact per-block count');
  const selected=list.items[0];assert.ok(selected,'Known authorized block fixture is nonempty');
  const detail=await renderedResponse(page,runtime.explorerOrigin,'/blocks/'+selected.number,()=>page.getByTestId('block-row').filter({has:page.locator(`a[href="/block/${selected.number}"]`)}).locator('a[href="/block/'+selected.number+'"]').click());
  const row=page.locator('[data-testid="info-row"][data-label="Transactions"]'),expected=await renderedBlockCount(row,detail,name+' block detail');
  const tab=page.getByTestId('tab-transactions');assert.ok((await tab.textContent()).includes(expected.text));
  for(const activation of ['click','Enter','Space']){
    await page.getByTestId('tab-details').click();
    await page.locator('[data-testid="tab-details"][aria-selected="true"]').waitFor({timeout:5000});await row.waitFor({state:'visible',timeout:5000});
    if(activation==='click')await tab.click();else{await tab.focus();await tab.press(activation);}
    // BrowserRouter may commit its navigation after the input action resolves.
    // Wait for the real selected child, retaining the explicit assertion below.
    await page.locator('[data-testid="tab-transactions"][aria-selected="true"]').waitFor({timeout:5000});await row.waitFor({state:'hidden',timeout:5000});
    assert.equal(await tab.getAttribute('aria-selected'),'true');const tooltip=page.getByRole('tooltip');await tooltip.waitFor();assert.ok(blockCountObservationMatches(detail,{count:expected.text,title:await tooltip.textContent()}),'Tab coverage and observation belong to the same block response');await page.keyboard.press('Escape');await tooltip.waitFor({state:'hidden'});
  }
  assert.equal(await tab.locator('button').count(),0,'Tab metadata contains no nested button');
  return {listRows:list.items.length,exactRows:exact,detailNumber:detail.number,detailCount:expected.text,oracle:'Each surface uses its own actual Block response; tab never derives count from its loaded transaction page'};
}
async function knownTransactionBlockCount(page,runtime,hash,screenshots) {
  assert.match(hash,/^0x[0-9a-f]{64}$/,'Existing private transaction fixture is required');
  const tx=await renderedResponse(page,runtime.explorerOrigin,'/transactions/'+hash,()=>page.goto(runtime.explorerOrigin+'/tx/'+hash));
  if(tx===null){await page.getByRole('heading',{name:'Transaction unavailable',exact:true}).waitFor();return {qualified:false,reason:'Existing authorized transaction fixture is unavailable; positive per-block UI is not live-qualified'};}
  assert.equal(tx.hash,hash);assert.ok(quantity(tx.blockNumber),'Known historical fixture is mined');
  const link=page.locator('[data-testid="info-row"][data-label="Block"]').locator(`a[href="/block/${tx.blockNumber}"]`);
  const block=await renderedResponse(page,runtime.explorerOrigin,'/blocks/'+tx.blockNumber,()=>link.click());
  if(block===null){await page.getByRole('heading',{name:'Block unavailable',exact:true}).waitFor();return {qualified:false,reason:'Existing transaction block is unavailable; positive per-block UI is not live-qualified'};}
  assert.equal(block.number,tx.blockNumber);
  const expected=await renderedBlockCount(page.locator('[data-testid="info-row"][data-label="Transactions"]'),block,'Deployer known-transaction block',true);
  if(expected.metric.status==='unavailable'){
    assert.ok(['history_pruned','index_floor'].includes(expected.metric.coverage),'Known existing transaction block must prove a numeric count unless its history is explicitly missing/pruned');
    return {qualified:false,blockNumber:block.number,coverage:expected.metric.coverage,reason:'Existing transaction block history is missing/pruned; positive per-block UI is not live-qualified'};
  }
  assert.ok(BigInt(expected.metric.value??expected.metric.lowerBound)>=1n,'Existing authorized transaction proves a positive historical block count');
  assert.ok((await page.getByTestId('tab-transactions').textContent()).includes(expected.text),'Positive tab badge uses the same block result');
  await page.screenshot({path:path.join(screenshots,'deployer-known-transaction-block-count.png'),fullPage:true,animations:'disabled'});
  return {qualified:true,blockNumber:block.number,count:expected.metric,oracle:'Existing ordinary Deployer transaction links to its own actual block response; count is positive without seeding or transaction-page inference'};
}
// Inspect painted text fragments, not just page overflow: fixed-height rows
// can overlap their neighbours while document.scrollWidth remains correct.
async function homeRowBounds(page) {
  const result = await page.getByTestId('tx-row').evaluateAll(rows => {
    const failures = [], heights = []; let badges = 0;
    for (let index=0;index<rows.length;index++) {
      const row=rows[index],box=row.getBoundingClientRect();heights.push(box.height);badges+=row.querySelectorAll('[data-testid="address-label"]').length;
      if(index && rows[index-1].getBoundingClientRect().bottom>box.top+1)failures.push({index,kind:'row overlap'});
      const walker=document.createTreeWalker(row,NodeFilter.SHOW_TEXT);
      while(walker.nextNode()) {
        const node=walker.currentNode;if(!node.textContent.trim())continue;
        const range=document.createRange();range.selectNodeContents(node);
        for(const rect of range.getClientRects())if(rect.width&&rect.height&&(rect.top<box.top-1||rect.bottom>box.bottom+1||rect.left<box.left-1||rect.right>box.right+1))failures.push({index,kind:'text outside own row'});
      }
    }
    return {rows:rows.length,badges,heights,failures};
  });
  assert.deepEqual(result.failures, [], 'Native Home hashes/party badges stay inside their own rows');
  return result;
}
async function homeAverage(page, blockPages, blockStatuses, expectedStatus) {
  await page.getByText('Avg Block Time', { exact:true }).waitFor();
  // Capture the rendered page and its derived value atomically: a later5s
  // poll may replace both while count tooltip checks continue.
  const rendered=await page.evaluate(()=>{const card=[...document.querySelectorAll('[data-testid="stat-card"]')].find(card=>card.textContent.includes('Avg Block Time'));return{blockRows:[...document.querySelectorAll('[data-testid="block-row"]')].map(row=>({number:row.querySelector('a[href^="/block/"]').getAttribute('href').split('/').at(-1),count:row.querySelector('button')?.textContent,title:row.querySelector('button')?.getAttribute('title')})),heights:[...document.querySelectorAll('[data-testid="block-row"] a[href^="/block/"]')].map(link=>link.getAttribute('href').split('/').at(-1)),value:card.querySelector('button').textContent,note:card.querySelector('[data-testid="block-time-sample"]').textContent};});
  const heights=rendered.heights,status=blockStatuses.at(-1);
  assert.equal(status,expectedStatus,'Known persona keeps its actual block-read permission');
  if(status===403) {
    assert.deepEqual(heights,[],'Denied blocks never create a rendered header sample');
    assert.equal(rendered.value,'Unavailable');
    assert.equal(rendered.note,'0 usable intervals · page range unavailable');
    const trigger=page.getByTestId('stat-card').filter({has:page.getByText('Avg Block Time',{exact:true})}).getByRole('button');
    await trigger.focus();await trigger.click();const tooltip=page.getByRole('tooltip');await tooltip.waitFor();assert.ok((await tooltip.textContent()).includes('No authorized block-page range is available.'));await page.keyboard.press('Escape');await tooltip.waitFor({state:'hidden'});
    return {value:'Unavailable',usablePairs:'0',blockStatus:status,source:'Actual403 block read; no authorized block-page range'};
  }
  const body=[...blockPages].reverse().find(body=>JSON.stringify(body.items.map(row=>row.number))===JSON.stringify(heights)&&body.items.every((block,index)=>blockCountObservationMatches(block,rendered.blockRows[index])));
  assert.ok(body,'Average oracle must use one actual response matching the rendered block page');
  let exactBlockCounts=0;
  for(let index=0;index<body.items.length;index++){const block=body.items[index],expected=blockCount(block),row=rendered.blockRows[index];assert.equal(row.number,block.number);assert.ok(blockCountObservationMatches(block,row));if(expected.metric.status==='exact')exactBlockCounts++;}
  assert.ok(exactBlockCounts>0,'Known block-authorized Home proves an actual exact per-block count');
  assert.equal(new Set(body.items.map(row=>row.number)).size,body.items.length);assert.equal(new Set(body.items.map(row=>row.hash)).size,body.items.length);
  const headers=body.items.filter(row=>row.number!=='0').map(row=>({height:BigInt(row.number),time:BigInt(row.timestamp)})).sort((a,b)=>a.height<b.height?-1:1);
  let seconds=0n,pairs=0n;
  for(let i=1;i<headers.length;i++)if(headers[i].height===headers[i-1].height+1n&&headers[i].time>headers[i-1].time){seconds+=headers[i].time-headers[i-1].time;pairs++;}
  assert.ok(pairs>0n,'Known block-authorized demo sample must contain a positive interval; no all-unavailable pass');
  const rounded=pairs?(seconds*200n+pairs)/(2n*pairs):undefined;
  const value=rounded===undefined?'Unavailable':(rounded/100n).toLocaleString('en-US')+'.'+String(rounded%100n).padStart(2,'0')+'s';
  const card=page.getByTestId('stat-card').filter({has:page.getByText('Avg Block Time',{exact:true})}),button=card.getByRole('button');
  await button.waitFor();assert.equal(rendered.value,value);
  if(headers.length)assert.equal(rendered.note,`${pairs} usable interval${pairs===1n?'':'s'} · page blocks ${headers[0].height}–${headers.at(-1).height}`);
  await button.focus();await button.click();const tooltip=page.getByRole('tooltip');await tooltip.waitFor();assert.ok((await tooltip.textContent()).includes('not a whole-chain or last-100-block average'));await page.keyboard.press('Escape');await tooltip.waitFor({state:'hidden'});
  return {value,usablePairs:String(pairs),blockStatus:status,exactBlockCounts,fromBlock:headers[0]?.height.toString(),throughBlock:headers.at(-1)?.height.toString(),source:'Single actual authorized rendered block-page response'};
}
function exactFlatFields(item, mapping) {
  for (const [flat, metric] of Object.entries(mapping)) if (Object.hasOwn(item, flat)) {
    assert.equal(item.counts?.[metric]?.status, 'exact', flat + ': lower bounds never enter exact fields');
    assert.equal(item[flat], item.counts[metric].value);
  }
}
export async function checkViewerCountRendering({ users, runtime, privateHash, screenshots, passed }) {
  const results = [], exactCurrentAccounts = [], numericHistory = []; let tokenDetails = 0, accountDetails = 0;
  for (const name of ['admin', 'deployer', 'reader']) {
    const page = users.get(name).page; await page.setViewportSize({ width: 1280, height: 900 });
    const blockPages=[],blockReads=[],blockStatuses=[];
    const collectBlocks=response=>{const url=new URL(response.url());if(url.origin!==runtime.explorerOrigin||url.pathname!=='/api/v2/explorer/blocks'||response.request().method()!=='GET'||url.searchParams.get('limit')!=='10')return;blockStatuses.push(response.status());if(response.status()===200)blockReads.push(response.json().then(body=>blockPages.push(body)).catch(()=>{/* Canceled old response is not an oracle. */}));};
    page.on('response',collectBlocks);
    let stats,average;
    try {
      stats = await renderedResponse(page, runtime.explorerOrigin, '/stats', () => page.goto(runtime.explorerOrigin));
      await page.getByRole('heading',{name:'Latest Blocks',exact:true}).waitFor();
      await page.getByText('Avg Block Time',{exact:true}).waitFor();
      await Promise.all(blockReads);
      average = await homeAverage(page,blockPages,blockStatuses,name==='reader'?403:200);
    } finally {page.off('response',collectBlocks);}
    assert.equal(await page.getByTestId('stat-card').count(),5,'Tokens remains beside the restored fifth average card');
    let mobileRows;
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      for (const [metric, label] of [['transactions', 'Visible Transactions'], ['accounts', 'Visible Accounts'], ['tokens', 'Visible Tokens']]) {
        await renderedCount(page.getByTestId('stat-card').filter({ has: page.getByText(label, { exact: true }) }), stats.counts?.[metric], name + ' ' + label, true);
      }
      if(width===390) mobileRows=await homeRowBounds(page);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Count cards/tooltips keep page within ' + width);
      await page.screenshot({ path: path.join(screenshots, name + '-viewer-counts-' + width + '.png'), fullPage: true, animations: 'disabled' });
    }
    if (stats.counts?.accounts?.status === 'exact' && stats.counts.accounts.consistency === 'CURRENT') exactCurrentAccounts.push(name);
    if (['exact', 'at_least'].includes(stats.counts?.transactions?.status)) numericHistory.push(name);
    await page.setViewportSize({ width: 1280, height: 900 });
    const blockSurfaces=name==='reader'?{qualification:'Actual403 block feed; no block count is inferred from another population'}:await blockCountSurfaces(page,runtime,name);
    const accounts = await renderedResponse(page, runtime.explorerOrigin, '/accounts', () => page.goto(runtime.explorerOrigin + '/accounts'));
    await page.getByRole('heading', { name: 'Accounts', exact: true }).waitFor();
    for (const account of accounts.items) {
      const row = page.getByTestId('account-row').filter({ has: page.locator(`a[href="/address/${account.address}"]`) });
      await row.waitFor(); exactFlatFields(account, { txCount: 'transactions', tokenTransferCount: 'tokenTransfers', internalTxCount: 'internalTransactions' });
      await renderedCount(row.locator('td').nth(2), account.counts?.transactions, name + ' account transactions');
      await renderedCount(row.locator('td').nth(3), account.counts?.tokenTransfers, name + ' account transfers');
    }
    if (accounts.items.length) {
      const address = accounts.items[0].address;
      const detail = await renderedResponse(page, runtime.explorerOrigin, `/addresses/${address}/stats`, () => page.goto(runtime.explorerOrigin + '/address/' + address));
      for (const [metric, label] of [['transactions', 'Transactions'], ['tokenTransfers', 'Token transfers'], ['internalTransactions', 'Internal txns']]) {
        const cell = page.locator('dt').filter({ hasText: new RegExp('^' + label + '$') }).locator('..');
        await renderedCount(cell, detail.counts?.[metric], name + ' address ' + metric);
      }
      accountDetails++;
    }
    const tokens = await renderedResponse(page, runtime.explorerOrigin, '/tokens', () => page.goto(runtime.explorerOrigin + '/tokens'));
    await page.getByRole('heading', { name: 'Tokens', exact: true }).waitFor();
    if (tokens.items.length) {
      await page.getByTestId('token-row').first().waitFor();
      const headings = await page.getByRole('columnheader').allTextContents();
      for (const token of tokens.items) {
        const row = page.getByTestId('token-row').filter({ has: page.locator(`a[href="/token/${token.address}"]`) });
        await row.waitFor(); exactFlatFields(token, { holderCount: 'holders', transferCount: 'tokenTransfers' });
        if (headings.includes('Indexed supply')) assert.equal((await row.locator('td').nth(headings.indexOf('Indexed supply')).textContent()).trim(), units(token.totalSupply, token.decimals));
        for (const [metric, label] of [['holders', 'Holders'], ['tokenTransfers', 'Transfers']]) if (headings.includes(label)) await renderedCount(row.locator('td').nth(headings.indexOf(label)), token.counts?.[metric], name + ' token ' + metric);
      }
      const address = tokens.items[0].address;
      const detail = await renderedResponse(page, runtime.explorerOrigin, `/tokens/${address}`, () => page.goto(runtime.explorerOrigin + '/token/' + address));
      for (const [metric, label] of [['holders', 'Holders'], ['tokenTransfers', 'Transfers']]) await renderedCount(page.locator(`[data-testid="stat-tile"][data-label="${label}"]`), detail.counts?.[metric], name + ' token detail ' + metric);
      if (detail.totalSupply !== undefined) {
        await page.locator('[data-testid="stat-tile"][data-label="Indexed supply"]').getByText(units(detail.totalSupply, detail.decimals), { exact: true }).waitFor();
        await page.getByText(/Indexed supply .*not a live contract read/).waitFor();
      }
      tokenDetails++;
    }
    results.push({ persona: name, stats: stats.counts, averageBlockTime: average, blockCounts:blockSurfaces, mobileHomeRows:mobileRows, returnedAccountRowsChecked: accounts.items.length, returnedTokenRowsChecked: tokens.items.length });
  }
  assert.ok(accountDetails > 0, 'Existing authorized demo accounts must exercise detail metadata');
  assert.ok(exactCurrentAccounts.some(name => name === 'admin' || name === 'deployer'), 'Small known method-authorized fixture must prove an exact CURRENT accounts count; all-unavailable is a failed restoration gate');
  assert.ok(numericHistory.length > 0, 'Small retained transaction fixture must prove a numeric exact/lower-bound metric; all-unavailable is a failed restoration gate');
  const positiveHistoricalBlock=await knownTransactionBlockCount(users.get('deployer').page,runtime,privateHash,screenshots);
  passed('viewer count cards/account cells match their authorized response; known CURRENT accounts and retained transactions are numeric; token coverage is recorded separately');
  return { personas: results, accountDetails, tokenDetails, exactCurrentAccounts, numericHistory, positiveHistoricalBlock, populatedTokenMetadataExercised: tokenDetails > 0, tokenCoverage: tokenDetails ? 'Actual authorized populated token rows checked' : 'Preserved DemoRecord/custom-event fixture has an empty authorized token feed. Populated supply/holder/transfer metadata is NOT live-browser-qualified; actual Go/PG engine and qualified component evidence remain separate.', oracle: 'Same rendered response only; no page size or separate CURRENT observation promoted to a total' };
}
export async function checkTransferTypeRendering({ users, runtime, screenshots, passed }) {
  const results = [];
  for (const name of ['admin', 'deployer', 'reader']) {
    const page = users.get(name).page;
    const verify = async (body, type) => {
      assert.ok(Array.isArray(body.items)); assert.equal(body.page.population, 'LIVE_RETAINED_INDEXED_ROWS_CURRENT_RIGHTS');
      if (type) assert.ok(body.items.every(row => row.tokenType === type), 'Real producer filters every returned row');
      if (body.items.length) await page.waitForFunction(({ hrefs, type }) => {
        const rows = [...document.querySelectorAll('[data-testid="transfer-row"]')];
        return JSON.stringify(rows.map(row => row.querySelector('td:first-child a')?.getAttribute('href'))) === JSON.stringify(hrefs) && (!type || rows.every(row => row.querySelector('td:nth-child(2)')?.textContent.includes(type.replace('ERC', 'ERC-'))));
      }, { hrefs: body.items.map(row => '/tx/' + row.txHash), type }, { timeout: 5000 });
      else await page.getByText('No token transfers on this visible page.', { exact: true }).waitFor();
      assert.equal(await page.getByTestId('transfer-row').count(), body.items.length);
      const rendered = await page.getByTestId('transfer-row').locator('td:first-child a').evaluateAll(links => links.map(link => link.getAttribute('href')));
      assert.deepEqual(rendered, body.items.map(row => '/tx/' + row.txHash));
    };
    let body = await renderedResponse(page, runtime.explorerOrigin, '/transfers', () => page.goto(runtime.explorerOrigin + '/token-transfers'));
    await verify(body, ''); let continued = false;
    if (body.page.next) {
      const cursor = body.page.next;
      body = await renderedResponse(page, runtime.explorerOrigin, '/transfers', () => page.getByRole('button', { name: 'Continue', exact: true }).click(), query => query.get('cursor') === cursor && !query.has('type'));
      await verify(body, ''); continued = true;
    }
    for (const type of ['ERC20', 'ERC721', 'ERC1155', 'ERC20', '']) {
      const label = type ? type.replace('ERC', 'ERC-') : 'All';
      body = await renderedResponse(page, runtime.explorerOrigin, '/transfers', () => page.getByRole('tab', { name: label, exact: true }).click(), query => (query.get('type') ?? '') === type && !query.has('cursor'));
      assert.equal(new URL(page.url()).searchParams.get('type') ?? '', type);
      await verify(body, type); assert.equal(await page.getByRole('tab', { name: label, exact: true }).getAttribute('aria-selected'), 'true');
      if (type === 'ERC20' && body.page.next && !continued) {
        const cursor = body.page.next;
        body = await renderedResponse(page, runtime.explorerOrigin, '/transfers', () => page.getByRole('button', { name: 'Continue', exact: true }).click(), query => query.get('type') === type && query.get('cursor') === cursor);
        await verify(body, type); continued = true;
      }
    }
    assert.equal(await page.getByText('Disclosed', { exact: true }).count(), 0);
    await page.screenshot({ path: path.join(screenshots, name + '-transfer-types.png'), fullPage: true, animations: 'disabled' });
    results.push({ persona: name, canonicalTypes: ['ERC20', 'ERC721', 'ERC1155'], reselectionStartsWithoutCursor: true, realContinuationExercised: continued });
  }
  passed('real transfer type tabs propagate canonical source filters and newly selected standards restart without a prior cursor');
  return { personas: results, limitation: 'Continuation only when existing authorized fixture returns one; terminal pages are not manufactured into a pagination scenario' };
}
