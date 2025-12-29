# Nishant Thakur's Personal Blog

Welcome to my personal blog repository! This site is built using [Jekyll](https://jekyllrb.com/) with the [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy) theme and hosted on GitHub Pages.

🌐 **Live Site:** [nishanthakur.github.io](https://nishanthakur.github.io/)

## About

This blog is where I share my thoughts, experiences, and insights on topics I'm passionate about. The site is designed to be clean, responsive, and easy to navigate.

## Features

- Fully responsive design
- Light/dark theme support
- Built-in search functionality
- Syntax highlighting for code blocks
- Category and tag organization
- Comment system support
- SEO optimized

## Technology Stack

- **Static Site Generator:** Jekyll 4.x
- **Theme:** [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy)
- **Hosting:** GitHub Pages
- **CI/CD:** GitHub Actions

## Local Development

To run this blog locally:

### Prerequisites

- Ruby 3.x
- Bundler
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/nishanthakur/nishanthakur.github.io.git
cd nishanthakur.github.io

# Install dependencies
bundle install

# Serve the site locally
bundle exec jekyll serve

# View at http://localhost:4000
```

## Project Structure

```
.
├── _data/              # Data files for customization
├── _posts/             # Blog posts (Markdown)
├── _tabs/              # Tab pages (About, Archives, etc.)
├── _plugins/           # Custom Jekyll plugins
├── assets/             # Images, CSS, JS files
├── _config.yml         # Site configuration
└── index.html          # Homepage
```

## Writing Posts

Posts are written in Markdown and stored in the `_posts` directory. File naming convention:

```
YYYY-MM-DD-title.md
```

Example front matter:

```yaml
---
title: "Your Post Title"
date: YYYY-MM-DD HH:MM:SS +/-TTTT
categories: [Category1, Category2]
tags: [tag1, tag2]
---
```

## Deployment

This site is automatically deployed using GitHub Actions. Any push to the `main` branch triggers a build and deployment to GitHub Pages.

## Customization

Key configuration files:
- `_config.yml` - Main site settings
- `_data/contact.yml` - Social media links
- `_data/share.yml` - Share button options

## License

This project is open source and available under the [MIT License](LICENSE).

## Contact

Feel free to reach out or connect with me through the social links on my blog!

---

Built with ❤️ using Jekyll and the Chirpy theme
