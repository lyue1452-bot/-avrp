import json

JSON_FILE = "/mnt/d/rayscan/rayscan_report.json"

with open(JSON_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

# 打印真实结构
print("==== 真实 JSON 结构（前2条） ====")
websites = data.get("WEBSITES", [])
if websites:
    site = websites[0]
    print("站点字段：", list(site.keys()))
    vulns = site.get("VULNS", [])
    if vulns:
        print("漏洞字段：", list(vulns[0].keys()))
        print("\n第一条漏洞：")
        print(json.dumps(vulns[0], ensure_ascii=False, indent=2))

