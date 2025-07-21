---
layout: page
title: Archive
permalink: /archive/
---

<div class="featured-articles">
  <div class="article-list">
    {% for post in site.posts %}
      <div class="article-item archive">
        <h3 class="article-title">
          <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
          <span class="arrow-icon"></span>
        </h3>
        <p class="article-meta">{{ post.date | date: "%Y-%m-%d" }}</p>
      </div>
    {% endfor %}
  </div>
</div>
