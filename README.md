# AI-Security-Lab

AI Security Lab is designed to benchmark AI models and AI agents against thousands of security-focused test cases, helping identify weaknesses before they can be exploited. The platform evaluates AI systems against adversarial scenarios including prompt injection, jailbreak attempts, instruction hijacking, policy bypasses, unsafe behavior, data-exfiltration attempts, tool and API misuse, privilege abuse, manipulation, misinformation, malicious agent actions, and other emerging AI-specific attack techniques. Its security testing methodology is built around recognized AI security guidance, with test cases aligned to areas covered by OWASP GenAI / LLM security recommendations and OWASP AI application security practices.

On the protection side, CyberPhylax is also developing AI Interceptor, our commercial AI security gateway designed to sit between AI agents, users, tools, and AI providers. AI Interceptor inspects prompts, responses, and agent actions using multiple security layers, including deterministic controls, semantic analysis, security classifiers, policy enforcement, and mandatory action gating.

In simple terms:

- **AI Security Lab tests your AI.**
- **AI Interceptor protects it in production.**

AI agents are quickly becoming capable of accessing APIs, files, databases, internal systems, and business workflows. As their capabilities increase, security testing and runtime protection can no longer be optional.

We are publishing AI Security Lab as open source because we believe the AI security community benefits from transparent tools, reproducible testing, and shared research.

Contributions, feedback, testing, and security research are welcome.

## Sample benchmark report

Explore the PDF report layout with **synthetic demonstration data**. These results
illustrate the reporting features; they are not measurements of any real model.

[Download the full sample PDF](docs/reports/sample-benchmark.pdf)

The report includes outcome and score charts, benchmark settings, every stored
record's pass/fail/error status, and full prompts, responses, and evaluator details.
This sample contains six records: three passed, two failed, and one provider error.

### Overview

![Sample PDF overview with score summary and outcome chart](docs/reports/sample-overview.png)

### Category scores

![Sample PDF category score chart and results table](docs/reports/sample-category-scores.png)

To generate your own report, open a benchmark run and export it as PDF.

<details>
<summary>Regenerate the sample assets</summary>

From the repository root, with project dependencies installed:

```bash
.venv/bin/python docs/reports/generate_sample.py
pdftoppm -f 1 -singlefile -scale-to 1400 -png docs/reports/sample-benchmark.pdf docs/reports/sample-overview
pdftoppm -f 3 -singlefile -scale-to 1400 -png docs/reports/sample-benchmark.pdf docs/reports/sample-category-scores
```

The PNG preview commands require Poppler's `pdftoppm` utility.

</details>
