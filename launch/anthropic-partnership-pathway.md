# Anthropic Partnership Pathway

Step-by-step guide to building a formal relationship with Anthropic and the broader agentskills.io ecosystem. The goal is official recognition of Anthropic-Cybersecurity-Skills as a reference implementation for cybersecurity agent skills.

---

## Phase 1: Spec Compliance Verification

**Timeline:** Before any outreach
**Goal:** Ensure every skill in the repo fully conforms to the agentskills.io specification

### Steps

1. **Review the agentskills.io specification**
   - Read the full spec at https://agentskills.io
   - Document every required and optional field in SKILL.md frontmatter
   - Document body structure requirements

2. **Audit all 611 skills for compliance**
   - Run automated validation against the spec
   - Check YAML frontmatter fields: name, description, version, tags, category
   - Verify body sections follow the expected structure
   - Fix any non-compliant skills

3. **Create a validation script**
   - Build a CI check that validates all SKILL.md files against the spec
   - Add it to GitHub Actions so future PRs are automatically validated
   - Document the validation process in CONTRIBUTING.md

4. **Self-certify compliance**
   - Add a badge or note in README: "agentskills.io compliant"
   - Reference the spec version you comply with

---

## Phase 2: Skill Directory Submissions

**Timeline:** After Phase 1 is complete
**Goal:** Get listed on official and community skill directories

### Target Directories

#### agentskill.sh
- **URL:** https://agentskill.sh
- **Action:** Submit the repo for listing as a cybersecurity skill collection
- **What to include:** Repo URL, skill count, subdomain coverage, compatibility list
- **Status:** [ ] Submitted [ ] Listed

#### SkillsMP (Skills Marketplace)
- **URL:** Check for current URL and submission process
- **Action:** Submit individual high-quality skills or the full collection
- **What to include:** Featured skills with descriptions, install instructions
- **Status:** [ ] Submitted [ ] Listed

#### skills.sh
- **URL:** https://skills.sh
- **Action:** Register the project and submit for directory listing
- **What to include:** Repo URL, category (cybersecurity), compatibility info
- **Status:** [ ] Submitted [ ] Listed

### Submission Template
```
Project: Anthropic-Cybersecurity-Skills
URL: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
Skills: 611+
Category: Cybersecurity
Subdomains: Threat detection, incident response, penetration testing,
  digital forensics, cloud security, network security, malware analysis,
  application security, identity & access management, compliance,
  security operations, cryptography
Standard: agentskills.io (SKILL.md format)
License: MIT
Compatibility: Claude Code, GitHub Copilot, OpenAI Codex CLI, Cursor,
  Windsurf, and 20+ AI platforms
```

---

## Phase 3: Engage the agentskills.io Community

**Timeline:** After directory submissions
**Goal:** Become a recognized contributor to the agentskills.io ecosystem

### Steps

1. **Open a discussion on agentskills/agentskills**
   - Repository: https://github.com/agentskills/agentskills (verify current URL)
   - Type: Discussion (not Issue)
   - Title: "Cybersecurity domain skills: 611+ skills available for community use"
   - Body: Introduce the project, explain the scope, invite feedback on skill quality and spec compliance
   - Tone: Collaborative, not promotional

2. **Discussion body template:**
   ```markdown
   ## Cybersecurity Skills Collection

   We've built a collection of 611+ cybersecurity skills following the
   agentskills.io standard. The skills cover 12 subdomains including threat
   detection, incident response, penetration testing, digital forensics,
   and cloud security.

   **Repo:** https://github.com/mukul975/Anthropic-Cybersecurity-Skills

   We'd love feedback from the community on:
   - Spec compliance -- are we following the standard correctly?
   - Skill quality -- are the methodologies accurate and useful?
   - Missing coverage -- what cybersecurity skills should we add?

   Happy to contribute these to the ecosystem in whatever way is most useful.
   ```

3. **Respond to feedback promptly**
   - Fix any spec compliance issues raised
   - Incorporate quality suggestions
   - Be responsive and collaborative

4. **Offer to help with the spec itself**
   - If there are open issues on the agentskills spec repo, contribute fixes
   - Propose cybersecurity-specific extensions if they would help the standard

---

## Phase 4: Engage Anthropic Developer Relations

**Timeline:** After community engagement shows traction (100+ stars, directory listings)
**Goal:** Get on Anthropic's radar for potential partnership or promotion

### Steps

1. **Identify contacts**
   - Anthropic Developer Relations team
   - Anthropic community forums and Discord
   - Anthropic blog / social media team
   - Claude Code product team

2. **Initial outreach**
   - Post in Anthropic's developer community (forum/Discord) about the project
   - Share how it enhances Claude Code's cybersecurity capabilities
   - Frame it as: "Here's what we built to make Claude better at security"

3. **Outreach message template:**
   ```
   Hi Anthropic team,

   We've built Anthropic-Cybersecurity-Skills, an open-source library of
   611+ cybersecurity skills for AI agents following the agentskills.io
   standard. It's designed to make Claude Code significantly more capable
   at security tasks -- threat detection, incident response, pentesting,
   forensics, and more.

   The project is MIT licensed, has [X] stars, and is listed on [directories].

   We'd love to discuss how this could be useful to the Claude ecosystem,
   whether through official promotion, integration, or collaboration.

   Repo: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
   ```

4. **Provide value first**
   - File bug reports on Claude Code's security capabilities
   - Write blog posts about using Claude Code for security tasks
   - Create tutorials that showcase Claude + cybersecurity skills
   - Be a visible, helpful member of the Anthropic community

---

## Phase 5: Submit Skills to anthropics/skills

**Timeline:** After Anthropic engagement
**Goal:** Get skills accepted into Anthropic's official skills repository

### Steps

1. **Identify the target repo**
   - Check https://github.com/anthropics/skills (or current equivalent)
   - Read their CONTRIBUTING.md and submission requirements
   - Understand their quality bar and review process

2. **Select 3-5 best skills for initial submission**
   - Choose skills that are:
     - Highest quality and most thoroughly tested
     - Broadly useful (not niche edge cases)
     - Well-structured and clearly written
     - Demonstrably effective when used by Claude
   - Recommended initial submissions:
     1. A threat detection / log analysis skill (most broadly useful)
     2. An incident response triage skill (high demand)
     3. A cloud security assessment skill (relevant to many users)
     4. A vulnerability analysis skill (practical and demonstrable)
     5. A security code review skill (directly relevant to coding agents)

3. **Polish selected skills**
   - Review each skill line by line for clarity and accuracy
   - Test each skill with Claude Code to verify it produces good results
   - Ensure perfect spec compliance
   - Add any fields or sections required by Anthropic's repo format

4. **Submit PRs**
   - One PR per skill (easier to review)
   - Clear PR descriptions explaining the skill's purpose and testing
   - Be responsive to review feedback
   - Do not submit all at once; space them out

5. **Follow up**
   - If PRs are not reviewed within 2 weeks, politely follow up
   - Incorporate any requested changes quickly
   - Once initial skills are accepted, propose a larger batch

---

## Success Criteria

| Milestone | Target | Status |
|-----------|--------|--------|
| All 611 skills pass spec validation | Phase 1 | [ ] |
| Listed on agentskill.sh | Phase 2 | [ ] |
| Listed on skills.sh | Phase 2 | [ ] |
| Discussion opened on agentskills/agentskills | Phase 3 | [ ] |
| Positive response from agentskills community | Phase 3 | [ ] |
| Posted in Anthropic developer community | Phase 4 | [ ] |
| Response from Anthropic team member | Phase 4 | [ ] |
| First skill accepted into anthropics/skills | Phase 5 | [ ] |
| 3+ skills accepted into anthropics/skills | Phase 5 | [ ] |
| Official mention or promotion by Anthropic | Phase 5 | [ ] |

---

## Timeline Summary

| Phase | Description | Estimated Duration | Prerequisites |
|-------|-------------|-------------------|---------------|
| 1 | Spec compliance verification | 1-2 weeks | None |
| 2 | Directory submissions | 1 week | Phase 1 |
| 3 | agentskills.io community engagement | 2-4 weeks | Phase 2 |
| 4 | Anthropic developer relations | 2-4 weeks | Phase 3 + traction |
| 5 | Submit to anthropics/skills | 2-4 weeks | Phase 4 |

Total estimated timeline: 2-3 months from start to first accepted skill in Anthropic's repo.
