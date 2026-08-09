# AI-Based Multi-Agent SAST for raspberrypi/userland

과제 산출물 리포지토리. 상세 설계/근거/결과는 report.md 참고.

## 대상 저장소

이 저장소에는 raspberrypi/userland 소스 코드 자체는 포함하지 않습니다.
아래처럼 별도로 클론해서 사용하세요.

git clone https://github.com/raspberrypi/userland.git

## 실행 방법

pip install google-genai
$env:GEMINI_API_KEY = "your-key-here"
python agent_pipeline.py B083 B097 B011
