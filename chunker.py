# chunker.py
import json
from pathlib import Path

ROOT = Path(".")
BATCH_LINE_CAP = 2500  # 구조적 상한 (정확한 토큰수는 이후 tiktoken으로 별도 실측)

PRIORITY_RULES = [
    (["containers"], 1, "외부 파일 포맷 파싱 (공격 표면 최상위)"),
    (["dtoverlay", "libfdt"], 1, "외부 바이너리(Device Tree) 파싱"),
    (["vcos"], 2, "동시성 프리미티브 (레이스컨디션 후보)"),
    (["vchiq_arm"], 3, "IPC 메시지 처리"),
    (["mmal"], 4, "미디어 파이프라인 버퍼 관리"),
    (["apps/raspicam", "hello_pi"], 5, "사용자 입력 처리 앱"),
    (["khronos"], 6, "GPU client 직렬화 stub"),
    (["vmcs_host"], 3, "IPC 메시지 처리"),
]

def get_priority(path_str):
    p = path_str.replace("\\", "/")
    for keywords, tier, reason in PRIORITY_RULES:
        if any(k in p for k in keywords):
            return tier, reason
    return 9, "기타"

dirs = {}
for c_file in ROOT.rglob("*.c"):
    d = str(c_file.parent)
    with open(c_file, encoding="utf-8", errors="ignore") as f:
        lines = sum(1 for _ in f)
    dirs.setdefault(d, []).append((str(c_file), lines))

batches, batch_id = [], 1
for d, files in dirs.items():
    tier, reason = get_priority(d)
    total = sum(l for _, l in files)
    if total <= BATCH_LINE_CAP:
        batches.append({"batch_id": f"B{batch_id:03d}", "dir": d, "tier": tier,
                         "reason": reason, "files": [f for f, _ in files], "lines": total})
        batch_id += 1
    else:
        cur, cur_lines = [], 0
        for f, l in sorted(files, key=lambda x: -x[1]):
            if cur_lines + l > BATCH_LINE_CAP and cur:
                batches.append({"batch_id": f"B{batch_id:03d}", "dir": d, "tier": tier,
                                 "reason": reason, "files": cur, "lines": cur_lines})
                batch_id += 1
                cur, cur_lines = [], 0
            cur.append(f); cur_lines += l
        if cur:
            batches.append({"batch_id": f"B{batch_id:03d}", "dir": d, "tier": tier,
                             "reason": reason, "files": cur, "lines": cur_lines})
            batch_id += 1

batches.sort(key=lambda b: b["tier"])
with open("../batch_manifest.json", "w", encoding="utf-8") as f:
    json.dump(batches, f, ensure_ascii=False, indent=2)

print(f"총 {len(batches)}개 배치 생성 → batch_manifest.json")
for b in batches[:10]:
    print(b["batch_id"], "tier", b["tier"], b["dir"], b["lines"], "lines")