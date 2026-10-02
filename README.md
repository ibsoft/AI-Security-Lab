At CyberPhylax, we believe AI security needs to be measurable, repeatable, and practical.

That is why we decided to open-source one of our tools: AI Security Lab

AI Security Lab is designed to benchmark AI models and AI agents against thousands of security-focused test cases, helping identify weaknesses before they can be exploited. The platform evaluates AI systems against adversarial scenarios including prompt injection, jailbreak attempts, instruction hijacking, policy bypasses, unsafe behavior, data-exfiltration attempts, tool and API misuse, privilege abuse, manipulation, misinformation, malicious agent actions, and other emerging AI-specific attack techniques. Its security testing methodology is built around recognized AI security guidance, with test cases aligned to areas covered by OWASP GenAI / LLM security recommendations and OWASP AI application security practices.


Security Testing Categories

Prompt Injection — direct and indirect prompt-injection attacks.

Jailbreak Attacks — attempts to bypass model safety controls and restrictions.

System Prompt Leakage — attempts to reveal hidden instructions, policies, or system context.

Sensitive Information Disclosure — extraction of secrets, credentials, private data, or confidential context.

Improper Output Handling — dangerous model output that could lead to XSS, command injection, SQL injection, code execution, or downstream compromise.

Excessive Agency — testing whether agents perform actions beyond their intended permissions or scope.

Tool & API Misuse — malicious or unauthorized use of tools, APIs, plugins, files, databases, and external services.

Data Exfiltration — attempts to extract sensitive information through prompts, tools, external URLs, or agent actions.

Privilege Escalation — attempts to make an agent obtain or use capabilities beyond its authorized privileges.

Policy Bypass — attempts to circumvent system, organization, or application security policies.

Instruction Hijacking — malicious instructions attempting to override the original task or trusted system instructions.

Data & Model Poisoning — scenarios involving malicious training data, retrieved content, memory, documents, or contextual information.

RAG / Vector Security — malicious retrieved documents, poisoned embeddings, context manipulation, and vector-store attacks.

Supply Chain Risks — threats involving models, libraries, datasets, plugins, tools, and external dependencies.

Misinformation & Hallucination — testing confidently incorrect, fabricated, misleading, or manipulated responses.

Unsafe Content & Behavior — evaluation of responses that violate defined security and safety policies.

Command & Code Injection — attempts to influence agents into executing malicious shell commands, scripts, SQL, or application code.

File System Abuse — unauthorized file reading, modification, deletion, traversal, or access to sensitive files.

SSRF & External Resource Abuse — attempts to make agents access unauthorized internal or external network resources.

Agent-to-Agent Attacks — malicious instructions or data passed between cooperating AI agents.

Memory Poisoning — attempts to insert malicious or misleading information into persistent agent memory.

Context Manipulation — manipulation of conversation history, retrieved context, metadata, or trusted sources.

Social Engineering & Manipulation — attacks designed to persuade the model or agent to ignore established controls.

Resource Abuse / Unbounded Consumption — excessive token usage, loops, recursive agent behavior, or resource exhaustion.

Adversarial Inputs — obfuscation, encoding, multilingual attacks, Unicode tricks, fragmented prompts, and other techniques intended to evade detection.



On the protection side, CyberPhylax is also developing AI Interceptor, our commercial AI security gateway designed to sit between AI agents, users, tools, and AI providers. AI Interceptor inspects prompts, responses, and agent actions using multiple security layers, including deterministic controls, semantic analysis, security classifiers, policy enforcement, and mandatory action gating.


In simple terms:

AI Security Lab tests your AI.

AI Interceptor protects it in production.

AI agents are quickly becoming capable of accessing APIs, files, databases, internal systems, and business workflows. As their capabilities increase, security testing and runtime protection can no longer be optional.


We are publishing AI Security Lab as open source because we believe the AI security community benefits from transparent tools, reproducible testing, and shared research.


Contributions, feedback, testing, and security research are welcome.


#CyberPhylax #AISecurity #ArtificialIntelligence #CyberSecurity #AIAgents #LLMSecurity #GenAI #PromptInjection #RedTeaming #OpenSource #OWASP #AIEngineering #AISafety

<img width="1915" height="955" alt="image" src="https://github.com/user-attachments/assets/5b56d885-5884-4cef-94a0-5e8e915f363a" />

<img width="1905" height="947" alt="image" src="https://github.com/user-attachments/assets/2025cc6e-cb9e-45c1-beef-3258a90ed104" />

<img width="1891" height="523" alt="image" src="https://github.com/user-attachments/assets/65b6369b-9012-44d3-8849-f3924d44c8d2" />

<img width="1903" height="951" alt="image" src="https://github.com/user-attachments/assets/d5050fbc-043e-46e1-9897-2353453d1ba0" />



