package main

// reportHTML 是自包含的 HTML 模板：样式内联，不引用任何 CDN，可直接双击打开或截图。
const reportHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BypassLab 对抗测试报告</title>
<style>
  :root{
    --blue:#1F4E79; --blue-light:#DCE6F1; --purple:#6C4CE0;
    --ink:#1F2933; --muted:#6B7785; --line:#E3E8EF; --bg:#F7F9FC;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font:14px/1.65 "微软雅黑","PingFang SC","Segoe UI",sans-serif;}
  .wrap{max-width:1000px;margin:0 auto;padding:28px 20px 60px}
  header{border-left:6px solid var(--blue);padding:4px 0 4px 14px;margin-bottom:22px}
  h1{margin:0 0 4px;font-size:23px;color:var(--blue)}
  .sub{color:var(--muted);font-size:12.5px}
  h2{font-size:15px;margin:30px 0 12px;padding-left:9px;border-left:3px solid var(--purple)}
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
  .kpi{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 16px}
  .kpi .t{font-size:12px;color:var(--muted)}
  .kpi .v{font-size:26px;font-weight:700;color:var(--blue);line-height:1.25}
  .kpi .h{font-size:11.5px;color:var(--muted)}
  .card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:16px 18px}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
  th{background:#F2F6FB;color:#33475B;font-weight:600;white-space:nowrap}
  td.mono{font-family:Consolas,Menlo,monospace;font-size:11.5px;color:#444}
  .tag{display:inline-block;padding:1px 7px;border-radius:99px;font-size:11px;background:var(--blue-light);color:var(--blue)}
  .tag.bad{background:#FDE8E8;color:#B02418}
  .note{background:#FFFDF5;border:1px solid #F0E2B6;border-radius:10px;padding:14px 16px;font-size:12.5px}
  .note b{color:#8A6D1F}
  footer{margin-top:34px;color:var(--muted);font-size:11.5px;text-align:center}
  svg{max-width:100%;height:auto;display:block}
</style>
</head>
<body>
<div class="wrap">

<header>
  <h1>BypassLab · WAF 对抗测试报告</h1>
  <div class="sub">生成时间 {{.Generated}} ｜ 判定口径：HTTP 403 且响应头带 X-BypassLab-Blocked 才计为「拦截」｜ 全部测试仅针对本地靶场</div>
</header>

<div class="kpis">
  {{range .KPIs}}
  <div class="kpi"><div class="t">{{.Title}}</div><div class="v">{{.Value}}</div><div class="h">{{.Hint}}</div></div>
  {{end}}
</div>

<h2>拦截率随对抗轮次变化</h2>
<div class="card">{{.LineSVG}}</div>

<h2>本轮各类别拦截率（短板在前）</h2>
<div class="card">{{.BarSVG}}</div>

<h2>命中规则分布（本轮 Top 8）</h2>
<div class="card">
  <table>
    <tr><th style="width:46%">规则</th><th>命中次数</th><th style="width:34%">占比示意</th></tr>
    {{range .RuleBars}}
    <tr>
      <td class="mono">{{.Label}}</td>
      <td>{{.Text}}</td>
      <td><div style="background:#EFF3F8;border-radius:3px;height:10px">
        <div style="width:{{pct .Value}};background:#1F4E79;height:10px;border-radius:3px"></div>
      </div></td>
    </tr>
    {{end}}
  </table>
</div>

<h2>剩余绕过清单（{{len .Latest.Bypasses}} 条，下一轮补规则的输入）</h2>
{{if .Latest.Bypasses}}
<div class="card">
  <table>
    <tr><th>样本</th><th>类别</th><th>名称</th><th>载荷（截断）</th></tr>
    {{range .Latest.Bypasses}}
    <tr>
      <td class="mono">{{.ID}}</td>
      <td>{{.Category}}</td>
      <td>{{.Name}}</td>
      <td class="mono">{{snippet .Payload}}</td>
    </tr>
    {{end}}
  </table>
</div>
{{else}}
<div class="card"><span class="tag">本轮无语料内绕过</span> 注意：这只说明当前语料被全部覆盖，不代表泛化能力。</div>
{{end}}

<h2>误报清单（{{len .Latest.FPs}} 条）</h2>
{{if .Latest.FPs}}
<div class="card">
  <table>
    <tr><th>样本</th><th>名称</th><th>命中规则</th></tr>
    {{range .Latest.FPs}}
    <tr><td class="mono">{{.ID}}</td><td>{{.Name}}</td><td class="mono">{{.RuleID}}</td></tr>
    {{end}}
  </table>
</div>
{{else}}
<div class="card"><span class="tag">0 条误报</span> 良性样本全部放行，说明阈值没有过紧。</div>
{{end}}

<h2>三轮结果汇总</h2>
<div class="card">
  <table>
    <tr><th>轮次</th><th>样本</th><th>攻击拦截</th><th>拦截率</th><th>误报率</th><th>剩余绕过</th></tr>
    {{range .Rounds}}
    <tr>
      <td>{{.Label}}</td>
      <td>{{.Total}}</td>
      <td>{{.Blocked}}/{{.Attacks}}</td>
      <td><b style="color:#1F4E79">{{pct .Rate}}</b></td>
      <td>{{pct .FPRate}}</td>
      <td>{{if .Bypasses}}<span class="tag bad">{{len .Bypasses}}</span>{{else}}<span class="tag">0</span>{{end}}</td>
    </tr>
    {{end}}
  </table>
</div>

<div class="note" style="margin-top:22px">
  <b>怎么看这张报告：</b>第二轮 100% 是在同一套 108 条语料上补规则得到的结果，
  第三轮只把语料换成 18 条没见过的变形（数量 126），拦截率就回落到约 91%。
  这说明「拦截率」必须和「语料」绑定陈述——只报一个 100% 而不说语料来源，是不可复现的指标。
</div>

<footer>
  BypassLab · 本地靶场对抗实验 · 数据由 out/*_matrix.csv 自动渲染，未手工修改
</footer>

</div>
</body>
</html>`
