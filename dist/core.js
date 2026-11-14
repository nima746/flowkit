const FlowCore = (() => {
  const sensitive = /password|passwd|secret|token|authorization|api[_-]?key|email|phone/i;
  function mask(v) { if(Array.isArray(v))return v.map(mask); if(v && typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,sensitive.test(k)?'[REDACTED]':mask(x)]));return v; }
  const tools = {
    pretty:{name:'JSON 格式化',icon:'{ }',category:'結構',description:'驗證並整理 JSON，讓資料更容易閱讀。',run:s=>JSON.stringify(JSON.parse(s),null,2)},
    minify:{name:'JSON 壓縮',icon:'↔',category:'結構',description:'移除 JSON 中不必要的空白。',run:s=>JSON.stringify(JSON.parse(s))},
    mask:{name:'敏感資料遮罩',icon:'◈',category:'隱私',description:'遮罩 JSON 中的密碼、Token、Email 與電話欄位。',run:s=>JSON.stringify(mask(JSON.parse(s)),null,2)},
    decode:{name:'Base64 解碼',icon:'B↓',category:'編碼',description:'支援 UTF-8 中文文字的 Base64 解碼。',run:s=>new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(s.trim()),c=>c.charCodeAt(0)))},
    encode:{name:'Base64 編碼',icon:'B↑',category:'編碼',description:'將 UTF-8 文字轉換為 Base64。',run:s=>btoa(Array.from(new TextEncoder().encode(s),b=>String.fromCharCode(b)).join(''))},
    urlDecode:{name:'URL 解碼',icon:'%↓',category:'編碼',description:'解開 URL 百分比編碼。',run:s=>decodeURIComponent(s)},
    urlEncode:{name:'URL 編碼',icon:'%↑',category:'編碼',description:'將文字轉為 URL component。',run:s=>encodeURIComponent(s)},
    unique:{name:'行去重',icon:'≠',category:'文字',description:'保留原順序，移除重複行。',run:s=>[...new Set(s.split(/\r?\n/))].join('\n')},
    sort:{name:'逐行排序',icon:'↓',category:'文字',description:'依文字順序排列每一行。',run:s=>s.split(/\r?\n/).sort((a,b)=>a.localeCompare(b,'zh-Hant')).join('\n')},
    trim:{name:'清除多餘空白',icon:'⌁',category:'文字',description:'移除每行頭尾空白與空白行。',run:s=>s.split(/\r?\n/).map(x=>x.trim()).filter(Boolean).join('\n')},
    hash:{name:'SHA-256 雜湊',icon:'#',category:'隱私',description:'使用瀏覽器密碼學 API 計算摘要。',run:async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s))),x=>x.toString(16).padStart(2,'0')).join('')}
  };
  function detect(s){try{JSON.parse(s);return {label:'JSON 資料',tool:'pretty'};}catch{}if(/%[0-9a-f]{2}/i.test(s))return {label:'可能是 URL 編碼',tool:'urlDecode'};if(s.trim()&&s.trim().length%4===0&&/^[A-Za-z0-9+/]+={0,2}$/.test(s.trim()))return {label:'可能是 Base64',tool:'decode'};return {label:'純文字',tool:'trim'};}
  async function execute(input,steps){let value=input;const trace=[];for(const id of steps){if(!tools[id])throw new Error('未知工具：'+id);try{value=await tools[id].run(value);trace.push({id,value});}catch(e){throw new Error('第 '+(trace.length+1)+' 步「'+tools[id].name+'」失敗：'+e.message);}}return {value,trace};}
  return {tools,detect,execute};
})();
if(typeof module!=='undefined')module.exports=FlowCore;
