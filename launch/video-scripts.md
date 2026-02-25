# Demo Video Scripts

Scripts for 3 launch demo videos. Each video targets a specific audience and goal.

---

## Video 1: Install & Demo -- Cybersecurity Skills for Claude Code

**Duration:** 3-5 minutes
**Target audience:** AI agent users, developers, security practitioners
**Goal:** Show installation and immediate value

### Title Card
```
Anthropic-Cybersecurity-Skills
611+ Cybersecurity Skills for AI Agents
github.com/mukul975/Anthropic-Cybersecurity-Skills
```

### Narration Script

**[0:00-0:15] Opening**

"What if your AI coding agent actually understood cybersecurity? Not just generic advice, but real, structured security skills it can follow step by step. That's exactly what Anthropic-Cybersecurity-Skills gives you. Let me show you."

**[0:15-0:45] What it is**

"Anthropic-Cybersecurity-Skills is an open-source library of over 611 cybersecurity skills built on the agentskills.io standard. Each skill is a structured SKILL.md file that any compatible AI agent can install and use. It covers threat detection, incident response, penetration testing, digital forensics, cloud security, network security, and more."

**[0:45-1:30] Installation**

"Let me show you how to install it. I'll open my terminal and clone the repository."

[Screen: terminal showing git clone]

"Now I'll tell Claude Code to use these skills. I add the skills directory to my project configuration."

[Screen: showing .claude/skills or equivalent configuration]

"That's it. The agent now has access to 611 cybersecurity skills."

**[1:30-3:00] Live Demo**

"Let's test it. I'll ask Claude to help me analyze a suspicious log file."

[Screen: Claude Code using a threat detection skill to analyze logs]

"Notice how the agent follows a structured methodology -- it's not guessing. It's following the skill's defined steps: identify indicators, correlate events, assess severity, and recommend response actions."

[Screen: showing the skill output with structured analysis]

"Let me try another one. I'll ask it to help with an incident response triage."

[Screen: Claude using an IR skill]

"Again, structured output following a defined methodology. This is the difference between an AI that gives generic security advice and one that follows professional security workflows."

**[3:00-3:30] Closing**

"All 611 skills are open source, free to use, and ready for you to install right now. Check out the repo at the link below, star it if you find it useful, and try installing skills into your own AI agent. Link in the description."

[Screen: GitHub repo page with star button highlighted]

### Screen Recording Checklist
- [ ] Clean terminal with readable font size (16pt+)
- [ ] Repo already cloned for speed (or show quick clone)
- [ ] Pre-staged log file for the threat detection demo
- [ ] Claude Code open and ready
- [ ] Screen resolution: 1920x1080
- [ ] Dark theme for terminal visibility
- [ ] Zoom in on key moments (skill output, structured results)
- [ ] No personal information visible on screen
- [ ] Test full flow end-to-end before recording

### YouTube Metadata

**Title:** Install 611 Cybersecurity Skills for Claude Code in 2 Minutes | AI Agent Security

**Description:**
```
Install 611+ cybersecurity skills for your AI coding agent. Works with Claude Code,
GitHub Copilot, Cursor, and 20+ platforms.

Get the skills: https://github.com/mukul975/Anthropic-Cybersecurity-Skills

Skills cover:
- Threat detection & hunting
- Incident response
- Penetration testing
- Digital forensics
- Cloud security (AWS, Azure, GCP)
- Network security
- Malware analysis
- And more

Built on the agentskills.io open standard.

#cybersecurity #aiagents #claudecode #security #hacking #infosec
```

**Tags:** cybersecurity, AI agents, Claude Code, security skills, threat detection, incident response, penetration testing, agentskills, open source, infosec, AI security, GitHub Copilot, Cursor, security automation

---

## Video 2: AI Agent vs. Real Security Task -- Testing Threat Hunting Skills

**Duration:** 5-8 minutes
**Target audience:** Security professionals, SOC analysts, threat hunters
**Goal:** Demonstrate real-world applicability and depth

### Title Card
```
AI Agent vs. Real Security Task
Testing Threat Hunting Skills
Anthropic-Cybersecurity-Skills
```

### Narration Script

**[0:00-0:30] Opening**

"Can an AI agent actually help with real threat hunting? Not toy examples, but actual security analysis work? I installed 611 cybersecurity skills into Claude Code and I'm going to put it to the test with a realistic threat hunting scenario."

**[0:30-1:30] Setup**

"Here's the scenario. We have a set of network logs and system events from what looks like a compromised environment. There are signs of lateral movement, possible data exfiltration, and some suspicious process execution. Let's see how the AI agent handles this with the cybersecurity skills installed."

[Screen: showing sample log data]

"I have the Anthropic-Cybersecurity-Skills library installed. The agent has access to threat detection skills, network analysis skills, and incident response skills. Let's go."

**[1:30-4:00] Threat Hunting Walkthrough**

"First, I'll ask the agent to perform initial threat hunting on these logs."

[Screen: Claude analyzing logs using threat hunting skill]

"Look at this. The agent is following a structured methodology from the threat hunting skill. It starts with hypothesis generation based on the available data, then moves to indicator identification."

[Screen: showing structured output with IOCs identified]

"It's found several indicators of compromise: unusual outbound connections, encoded PowerShell commands, and registry modifications consistent with persistence mechanisms. Let's dig deeper."

[Screen: asking Claude to investigate lateral movement indicators]

"Now it's correlating events across multiple log sources, mapping to MITRE ATT&CK techniques. T1059 Command and Scripting Interpreter, T1547 Boot or Logon Autostart Execution, T1071 Application Layer Protocol for the C2 channel."

[Screen: showing ATT&CK mapping output]

**[4:00-5:30] Analysis Quality**

"What makes this useful isn't just that it found things -- any grep command could find suspicious strings. The value is in the structured analysis. The skill guides the agent through a repeatable methodology: collect, correlate, hypothesize, validate, and document."

"Compare this to asking a generic AI the same question without these skills. You'd get a wall of text with generic advice. With the skills installed, you get structured, actionable output that follows professional security workflows."

**[5:30-6:30] Closing**

"This is one scenario across one set of skills. The library has 611 skills covering 12 cybersecurity subdomains. Threat detection, incident response, pentesting, forensics, cloud security, and more."

"If you're a security professional who uses AI tools, these skills make your agent significantly more capable. Link to the repo in the description. Star it, try it, and let me know what you think."

### Screen Recording Checklist
- [ ] Prepare realistic (but safe) log samples in advance
- [ ] Pre-test the full scenario to ensure compelling output
- [ ] Have ATT&CK framework reference ready for cross-checking
- [ ] Screen resolution: 1920x1080, dark theme
- [ ] Record agent output in real-time (no speedup on analysis sections)
- [ ] Highlight key findings with cursor or annotations
- [ ] Prepare fallback if agent output differs from expected

### YouTube Metadata

**Title:** AI Agent Threat Hunting Test: Can Claude Code Analyze Real Security Logs?

**Description:**
```
Testing whether an AI agent with 611 cybersecurity skills can perform real threat hunting.
Using Claude Code with Anthropic-Cybersecurity-Skills installed.

Get the skills: https://github.com/mukul975/Anthropic-Cybersecurity-Skills

In this video:
- Realistic threat hunting scenario with network and system logs
- AI agent following structured threat detection methodology
- IOC identification and correlation
- MITRE ATT&CK technique mapping
- Comparison with vs without cybersecurity skills installed

#threathunting #cybersecurity #aiagents #soc #infosec #mitreattack
```

**Tags:** threat hunting, cybersecurity, AI agents, SOC analyst, Claude Code, MITRE ATT&CK, incident response, log analysis, IOC, threat detection, security automation, AI security

---

## Video 3: Contributing Your First Cybersecurity Skill (SKILL.md Tutorial)

**Duration:** 5-7 minutes
**Target audience:** Open-source contributors, security practitioners wanting to contribute
**Goal:** Lower the barrier to contribution, grow the community

### Title Card
```
Contributing Your First Cybersecurity Skill
A SKILL.md Tutorial
Anthropic-Cybersecurity-Skills
```

### Narration Script

**[0:00-0:30] Opening**

"Want to contribute a cybersecurity skill that AI agents around the world can use? In the next few minutes, I'll walk you through writing your first SKILL.md file and submitting it to the Anthropic-Cybersecurity-Skills project. It's easier than you think."

**[0:30-1:30] Understanding the Format**

"Every skill in this project is a single file called SKILL.md. It follows the agentskills.io standard, which means any compatible AI agent can read and use it. Let me show you the structure."

[Screen: open an existing SKILL.md file]

"The file has YAML frontmatter at the top with metadata -- the skill name, description, version, tags, and category. Then the body contains the actual skill content in Markdown: an overview, step-by-step methodology, tools and commands, and expected outputs."

[Screen: highlighting each section]

"Think of it as writing a structured playbook that an AI agent will follow. You're encoding your security expertise into a format that machines can use."

**[1:30-3:30] Writing a Skill**

"Let's write one from scratch. I'll create a skill for analyzing suspicious email headers -- a common security task."

[Screen: create new directory and SKILL.md file]

"First, the frontmatter. I'll set the name, description, category, and tags."

[Screen: typing YAML frontmatter]

"Now the body. I start with an overview explaining what this skill does and when to use it. Then I write the step-by-step methodology."

[Screen: typing the skill body]

"Step 1: Extract and parse email headers. Step 2: Analyze the Received chain for anomalies. Step 3: Check SPF, DKIM, and DMARC results. Step 4: Investigate sender reputation. Step 5: Document findings and recommend action."

"For each step, I include the specific commands, tools, or techniques the AI agent should use. The more concrete and actionable, the better the skill works."

[Screen: completing the skill with tools and expected outputs]

**[3:30-5:00] Submitting a PR**

"Now let's submit this as a contribution. I'll fork the repo, create a branch, add my skill, and open a pull request."

[Screen: git workflow]

"Fork the repo. Create a branch named for your skill. Add your SKILL.md file in the correct subdomain directory. Commit with a clear message."

[Screen: showing PR creation on GitHub]

"In the PR description, explain what your skill does and why it's useful. The maintainers will review it and provide feedback."

**[5:00-5:45] Tips and Closing**

"A few tips for writing great skills. First, be specific -- vague instructions produce vague results. Second, include real tool names and commands when applicable. Third, structure your steps in a logical order that a security professional would follow. Fourth, test it by actually asking an AI agent to use your skill before you submit."

"The project has over 611 skills already, but there's always room for more. Check the issues tab for skill requests, or contribute something from your own expertise. Every contribution helps make AI agents better at cybersecurity. Link in the description."

### Screen Recording Checklist
- [ ] Have an existing SKILL.md open as reference
- [ ] Pre-plan the example skill (email header analysis) but type live
- [ ] Show the git fork/branch/PR workflow step by step
- [ ] Use GitHub web UI for the PR creation (more visual)
- [ ] Screen resolution: 1920x1080
- [ ] Split screen: editor on left, preview on right (if possible)
- [ ] Show CONTRIBUTING.md guidelines briefly
- [ ] Test the finished skill with an AI agent as a bonus segment

### YouTube Metadata

**Title:** Write Your First AI Cybersecurity Skill in 5 Minutes | SKILL.md Tutorial

**Description:**
```
Step-by-step tutorial for contributing a cybersecurity skill to the
Anthropic-Cybersecurity-Skills open-source project.

Get started: https://github.com/mukul975/Anthropic-Cybersecurity-Skills

In this video:
- Understanding the SKILL.md format (agentskills.io standard)
- Writing a skill from scratch (email header analysis example)
- Submitting your contribution via GitHub PR
- Tips for writing effective security skills

No prior open-source contribution experience needed.

#opensource #cybersecurity #tutorial #aiagents #contributing #github
```

**Tags:** open source contribution, SKILL.md, agentskills, cybersecurity, tutorial, GitHub, pull request, AI agents, security skills, Claude Code, how to contribute, beginner friendly

---

## Production Notes

### Recording Setup
- **Screen recording:** OBS Studio (free) or ScreenFlow (Mac)
- **Audio:** External USB microphone recommended; record in quiet room
- **Resolution:** 1920x1080 minimum, 4K preferred
- **Frame rate:** 30fps for screen recordings
- **Format:** MP4 (H.264) for upload

### Editing Checklist
- [ ] Add title cards at beginning and end
- [ ] Add subscribe/star callout overlays
- [ ] Speed up typing sections (1.5-2x) to maintain pacing
- [ ] Add chapter markers for YouTube
- [ ] Add captions/subtitles (YouTube auto-captions + manual review)
- [ ] Include repo link as pinned comment

### Thumbnail Design
- High contrast text on dark background
- Include "611 Skills" or key number
- Show terminal/code screenshot in background
- Use consistent branding across all 3 videos
