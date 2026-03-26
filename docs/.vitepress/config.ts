import { defineConfig } from 'vitepress'

export default defineConfig({
  lang: 'en-US',
  title: 'Phirewall',
  description: 'Protect your PHP application with a single middleware',

  head: [
    ['link', { rel: 'icon', href: '/logo.svg' }],
  ],

  appearance: true, // allow user to toggle light/dark

  themeConfig: {
    logo: { src: '/logo.svg', alt: 'Phirewall' },

    nav: [
      { text: 'Guide', link: '/getting-started' },
      { text: 'Features', link: '/features/safelists-blocklists' },
      { text: 'Recipes', link: '/common-attacks' },
      { text: 'Examples', link: '/examples' },
      { text: 'FAQ', link: '/faq' },
      {
        text: 'Flowd GmbH',
        link: 'https://flowd.de'
      }
    ],

    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Installation & Quick Start', link: '/getting-started' },
        ]
      },
      {
        text: 'Features',
        items: [
          { text: 'Safelists & Blocklists', link: '/features/safelists-blocklists' },
          { text: 'Rate Limiting', link: '/features/rate-limiting' },
          { text: 'Fail2Ban & Allow2Ban', link: '/features/fail2ban' },
          { text: 'Bot Detection & Matchers', link: '/features/bot-detection' },
          { text: 'OWASP Core Rule Set', link: '/features/owasp-crs' },
          { text: 'Storage Backends', link: '/features/storage' },
        ]
      },
      {
        text: 'Advanced',
        items: [
          { text: 'Dynamic Throttle & Sliding Window', link: '/advanced/dynamic-throttle' },
          { text: 'Request Context', link: '/advanced/request-context' },
          { text: 'Track & Notifications', link: '/advanced/track-notifications' },
          { text: 'Observability', link: '/advanced/observability' },
          { text: 'Infrastructure Adapters', link: '/advanced/infrastructure' },
          { text: 'PSR-17 Factories', link: '/advanced/psr17' },
          { text: 'Discriminator Normalizer', link: '/advanced/discriminator-normalizer' },
        ]
      },
      {
        text: 'Recipes & Reference',
        items: [
          { text: 'Common Attacks', link: '/common-attacks' },
          { text: 'Examples', link: '/examples' },
          { text: 'FAQ', link: '/faq' },
        ]
      },
      {
        text: 'More',
        items: [
          { text: 'Professional Services', link: '/services' },
          { text: 'Privacy Policy', link: '/privacy' },
          { text: 'Legal Notice (Imprint)', link: '/imprint' },
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/flowd/phirewall' }
    ],

    footer: {
      message: 'Dual licensed under LGPL-3.0-or-later and proprietary. | <a href="/imprint">Legal Notice (Imprint)</a>',
      copyright: 'Built by <a href="https://flowd.de" target="_blank" rel="noopener noreferrer">Flowd GmbH<span class="visually-hidden"> (opens in new tab)</span></a>'
    },

    search: {
      provider: 'local'
    },

    editLink: {
      pattern: 'https://github.com/flowd/phirewall-docs/edit/main/docs/:path'
    }
  },

  markdown: {
    theme: {
      dark: 'one-dark-pro',
      light: 'github-light'
    }
  }
})
