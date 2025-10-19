---
layout: page
title: Archive
permalink: /archive/
---

<div class="featured-articles archive-page">
  <div class="article-list">
    {% for post in site.posts %}
    <a href="{{ post.url | relative_url }}" class="article-link">
      <article class="article-item archive">
        <h3 class="article-title">
          {{ post.title }}
        </h3>
        <div class="article-meta">
          {{ post.date | date: "%Y年%m月%d日" }}
          {% if post.categories %}
          - {{ post.categories | join: ", " }}
          {% endif %}
        </div>
        <div class="arrow-icon"></div>
      </article>
    </a>
    {% endfor %}
  </div>
</div>
