---
layout: page
title: Contact
permalink: /contact/
---

<div class="contact-content">

<h2>与我联系</h2>

<p>无论是技术讨论、合作机会，还是简单的问候，我都很乐意听到你的声音。</p>

<h3>联系方式</h3>

<ul>
<li><strong>邮箱</strong>：<a href="mailto:{{ site.email }}">{{ site.email }}</a></li>
<li><strong>GitHub</strong>：<a href="https://github.com/{{ site.social.github }}">github.com/{{ site.social.github }}</a></li>
<li><strong>LinkedIn</strong>：<a href="https://linkedin.com/in/{{ site.social.linkedin }}">linkedin.com/in/{{ site.social.linkedin }}</a></li>
</ul>

<h3>我特别欢迎以下类型的交流</h3>

<ul>
<li><strong>技术讨论</strong>：网页抓取、Python开发、自动化工具相关的技术问题</li>
<li><strong>项目合作</strong>：如果你有有趣的项目想法，我很愿意参与讨论</li>
<li><strong>经验分享</strong>：关于产品开发、技术学习的经验交流</li>
<li><strong>反馈建议</strong>：对我的博客内容或项目的建议和反馈</li>
</ul>

<h3>发送消息</h3>

<p>请随时通过邮箱联系我，我通常会在24小时内回复。如果是技术相关的问题，请尽量详细描述你遇到的情况，这样我能更好地为你提供帮助。</p>

<div class="contact-form">
    <form name="contact" method="POST" data-netlify="true" netlify-honeypot="bot-field">
        <input type="hidden" name="form-name" value="contact" />
        <input type="hidden" name="bot-field" />
        
        <div class="form-group">
            <label for="name">姓名</label>
            <input type="text" id="name" name="name" required>
        </div>
        
        <div class="form-group">
            <label for="email">邮箱</label>
            <input type="email" id="email" name="email" required>
        </div>
        
        <div class="form-group">
            <label for="subject">主题</label>
            <input type="text" id="subject" name="subject" required>
        </div>
        
        <div class="form-group">
            <label for="message">消息</label>
            <textarea id="message" name="message" placeholder="请描述你的问题或想法..." required></textarea>
        </div>
        
        <button type="submit" class="submit-btn">发送消息</button>
    </form>
</div>

### 响应时间

- **邮箱回复**：通常24小时内
- **技术问题**：会优先回复，通常12小时内
- **项目合作**：详细回复可能需要2-3天时间

期待与你的交流！

</div>