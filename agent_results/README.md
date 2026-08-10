# agent_results/ 디렉터리 구조 안내

report.md의 리뷰·정정 과정(§8.3, §9, §14.7)에서 재구성된 디렉터리입니다. 기존에 저장소 루트의 `agent_results/*.json`(평평한 구조)으로 올라가 있던 파일들을 대체합니다.

## 왜 세 폴더로 나눴는가

기존 구조는 스크립트가 실행할 때마다 같은 파일명(`agent_results/B083.json` 등)에 덮어써서, **먼저 실행한 Run A(실제 CONFIRMED/REJECTED 판정이 담긴 핵심 실험)의 결과가 나중에 실행한 Run B(모델 등급을 낮춘 재현성 실험)로 덮여 사라지는 문제**가 있었습니다. report.md가 인용하는 실험 결과와 저장소에 남은 파일이 서로 다른 상태였던 것입니다.

```
agent_results/
├── run_A_gemini_flash/       # 실제 실험 결과 (gemini-3.6-flash). report.md §8.2, §8.3, §10, §11.1의 근거.
│   ├── B011.json             #   B011: CWE-416 CONFIRMED → 사람 재검증 후 REJECTED (원본 그대로 보존 + 정정 사유 별도 필드)
│   ├── B083.json             #   B083: CWE-476 CONFIRMED(유지) + CWE-120 2건(구문적 환각으로 REJECTED)
│   └── B097.json             #   B097: 2건 모두 REJECTED (자체 검증 정상 작동)
│
├── run_B_flash_lite/          # 모델 등급 교체 실험 (gemini-flash-lite-latest). report.md §8.4의 근거.
│   ├── B011.json              #   0건
│   ├── B083.json              #   0건
│   └── B097.json              #   0건
│
└── manual_ground_truth/       # 사람이 코드를 직접 추적/대조해 만든 정답지. report.md §9의 근거.
    ├── B011.json               #   CWE-362 RUNTIME_VALIDATION_REQUIRED + B011 CWE-416의 정정 사유(가드 절 코드 인용 포함)
    ├── B083.json               #   CWE-476 CONFIRMED, 자동 파이프라인의 환각 2건에 대한 판정 근거
    └── B097.json               #   mp4_cache_table 클램핑 로직 추적 결과 REJECTED
```

## 원칙

- **Run A 원본 JSON은 수정하지 않았습니다.** LLM이 실제로 뭐라고 말했는지 그 자체가 감사 추적(audit trail)으로서 기록 가치가 있기 때문입니다. 이후 판정이 뒤집힌 항목(B011의 CWE-416)도 원본 CONFIRMED 판정을 지우지 않고 `_later_correction` 필드로 정정 사유만 덧붙였습니다.
- **정정의 최종 근거는 `manual_ground_truth/`에 있습니다.** B011.json에는 실제 저장소 코드에서 발췌한 가드 절(guard clause) 3곳을 직접 인용해, "왜 REJECTED인지"를 재현 가능하게 남겼습니다.
- Run B의 배치별 토큰 세부값 일부는 세션 로그에 합산치만 남아 있어 `null`로 정직하게 표기했습니다(§14.9 향후 과제 — 재실행 시 정확한 값 확보).

## report.md와의 대응

| report.md 절 | 근거 파일 |
|---|---|
| §8.2 (Run A 실행 결과) | `run_A_gemini_flash/*.json` |
| §8.3 (B011 정정 과정) | `run_A_gemini_flash/B011.json` + `manual_ground_truth/B011.json` |
| §8.4 (Run B 모델 교체 실험) | `run_B_flash_lite/*.json` |
| §9 (사람 vs 자동 교차검증) | `manual_ground_truth/*.json` vs `run_A_gemini_flash/*.json` |
| §10 (환각 3건) | `run_A_gemini_flash/B083.json`(사례 1·2), `run_A_gemini_flash/B011.json`(사례 3) |