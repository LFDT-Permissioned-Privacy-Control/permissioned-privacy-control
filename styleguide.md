# Gateway Style Guide

Based on [Gateway.fm](https://gateway.fm/) design system.

---

## Color Palette

### Primary Purple
The signature Gateway purple is the primary brand color.

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| **Primary** | `#8950FA` | `rgb(137, 80, 250)` | Main accent, CTAs, links |
| Primary Light | `#A478FC` | `rgb(164, 120, 252)` | Hover states, highlights |
| Primary Lighter | `#C4A8FD` | `rgb(196, 168, 253)` | Subtle accents |
| Primary Lowest | `#F5F3FF` | `rgb(245, 243, 255)` | Backgrounds, hover states |
| Primary Dark | `#6B3DD4` | `rgb(107, 61, 212)` | Active states, emphasis |

### Neutrals
Clean, professional grays for text and UI.

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| Neutral 900 | `#0F0F0F` | `rgb(15, 15, 15)` | Primary text, headings |
| Neutral 800 | `#1A1A1A` | `rgb(26, 26, 26)` | Secondary text |
| Neutral 700 | `#374151` | `rgb(55, 65, 81)` | Body text |
| Neutral 500 | `#6B7280` | `rgb(107, 114, 128)` | Muted text, labels |
| Neutral 300 | `#CBD5E1` | `rgb(203, 213, 225)` | Borders, dividers |
| Neutral 200 | `#E2E8F0` | `rgb(226, 232, 240)` | Light borders |
| Neutral 100 | `#F1F5F9` | `rgb(241, 245, 249)` | Page background |
| Neutral 50 | `#FFFFFF` | `rgb(255, 255, 255)` | Cards, surfaces |

### Status Colors

| Name | Hex | Usage |
|------|-----|-------|
| Success | `#22C55E` | Confirmed transactions, positive states |
| Success Light | `#DCFCE7` | Success backgrounds |
| Warning | `#EAB308` | Pending states, cautions |
| Warning Light | `#FEF9C3` | Warning backgrounds |
| Error | `#EF4444` | Failed transactions, errors |
| Error Light | `#FEE2E2` | Error backgrounds |
| Info | `#8950FA` | Information (uses primary) |

---

## Typography

### Font Family
```css
/* Primary font - Gotham or fallback */
font-family: 'Gotham', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;

/* Monospace for addresses, hashes, code */
font-family: 'JetBrains Mono', 'SF Mono', 'Monaco', 'Consolas', monospace;
```

### Type Scale

| Element | Size | Weight | Line Height |
|---------|------|--------|-------------|
| H1 | 32px / 2rem | Bold (700) | 1.2 |
| H2 | 24px / 1.5rem | Bold (700) | 1.2 |
| H3 | 20px / 1.25rem | Semibold (600) | 1.3 |
| H4 | 18px / 1.125rem | Semibold (600) | 1.4 |
| Body | 16px / 1rem | Regular (400) | 1.5 |
| Body Small | 14px / 0.875rem | Regular (400) | 1.5 |
| Caption | 12px / 0.75rem | Medium (500) | 1.4 |
| Mono | 14px / 0.875rem | Regular (400) | 1.5 |

---

## Spacing

Based on 4px grid system.

| Token | Value | Usage |
|-------|-------|-------|
| xs | 4px | Tight spacing, icons |
| sm | 8px | Inner padding, gaps |
| md | 16px | Standard padding |
| lg | 24px | Section spacing |
| xl | 32px | Large sections |
| 2xl | 48px | Page sections |
| 3xl | 64px | Major sections |

---

## Border Radius

| Token | Value | Usage |
|-------|-------|-------|
| sm | 6px | Buttons, inputs, badges |
| md | 8px | Small cards, dropdowns |
| lg | 12px | Medium cards |
| xl | 16px | Large cards |
| 2xl | 24px | Hero sections, modals |
| full | 9999px | Pills, avatars, round buttons |

---

## Shadows

```css
/* Card shadow - subtle elevation */
--shadow-card: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.1);

/* Elevated shadow - modals, dropdowns */
--shadow-elevated: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);

/* Large shadow - popovers */
--shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);

/* Purple glow for primary elements */
--shadow-primary: 0 0 20px rgba(137, 80, 250, 0.3);
```

---

## Components

### Buttons

**Primary Button**
```css
.btn-primary {
  background: #8950FA;
  color: #FFFFFF;
  padding: 12px 24px;
  border-radius: 9999px; /* fully rounded */
  font-weight: 500;
  transition: all 0.2s ease;
}
.btn-primary:hover {
  background: #6B3DD4;
  box-shadow: 0 0 20px rgba(137, 80, 250, 0.4);
}
```

**Secondary Button**
```css
.btn-secondary {
  background: #FFFFFF;
  color: #0F0F0F;
  padding: 12px 24px;
  border: 1px solid #CBD5E1;
  border-radius: 9999px;
  font-weight: 500;
  transition: all 0.2s ease;
}
.btn-secondary:hover {
  background: #F5F3FF;
  border-color: #8950FA;
}
```

**Ghost Button**
```css
.btn-ghost {
  background: transparent;
  color: #8950FA;
  padding: 12px 24px;
  border-radius: 9999px;
  font-weight: 500;
}
.btn-ghost:hover {
  background: #F5F3FF;
}
```

### Cards

**Standard Card**
```css
.card {
  background: #FFFFFF;
  border: 1px solid #E2E8F0;
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}
```

**Feature Card (with accent)**
```css
.card-feature {
  background: #F5F3FF;
  border: 2px solid #C4A8FD;
  border-radius: 24px;
  padding: 32px;
}
```

### Inputs

```css
.input {
  background: #FFFFFF;
  border: 1px solid #CBD5E1;
  border-radius: 8px;
  padding: 12px 16px;
  font-size: 14px;
  transition: all 0.2s ease;
}
.input:focus {
  outline: none;
  border-color: #8950FA;
  box-shadow: 0 0 0 3px rgba(137, 80, 250, 0.2);
}
.input::placeholder {
  color: #6B7280;
}
```

### Badges / Tags

**Status Badge**
```css
.badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 12px;
  border-radius: 9999px;
  font-size: 12px;
  font-weight: 500;
}
.badge-success {
  background: #DCFCE7;
  color: #166534;
}
.badge-warning {
  background: #FEF9C3;
  color: #854D0E;
}
.badge-error {
  background: #FEE2E2;
  color: #991B1B;
}
.badge-primary {
  background: #F5F3FF;
  color: #8950FA;
}
```

### Tables

```css
.table {
  width: 100%;
  border-collapse: collapse;
}
.table th {
  text-align: left;
  padding: 12px 16px;
  font-size: 12px;
  font-weight: 500;
  color: #6B7280;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid #E2E8F0;
}
.table td {
  padding: 16px;
  border-bottom: 1px solid #F1F5F9;
}
.table tr:hover {
  background: #F5F3FF;
}
```

---

## Tailwind CSS Configuration

If using Tailwind, add these to `tailwind.config.js`:

```js
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#8950FA',
          50: '#F5F3FF',
          100: '#EDE9FE',
          200: '#C4A8FD',
          300: '#A478FC',
          400: '#8950FA',
          500: '#8950FA',
          600: '#6B3DD4',
          700: '#5B32B0',
          800: '#4C2889',
          900: '#3D1F6D',
        },
        neutral: {
          50: '#FFFFFF',
          100: '#F1F5F9',
          200: '#E2E8F0',
          300: '#CBD5E1',
          400: '#94A3B8',
          500: '#6B7280',
          600: '#475569',
          700: '#374151',
          800: '#1A1A1A',
          900: '#0F0F0F',
        },
      },
      fontFamily: {
        sans: ['Gotham', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'SF Mono', 'monospace'],
      },
      borderRadius: {
        'xl': '16px',
        '2xl': '24px',
      },
      boxShadow: {
        'card': '0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.1)',
        'primary': '0 0 20px rgba(137, 80, 250, 0.3)',
      },
    },
  },
};
```

---

## Light Theme (Default)

The Gateway design uses a **light theme** by default:
- Page background: `#F1F5F9` (light slate)
- Cards: `#FFFFFF` (white)
- Text: Dark neutrals (`#0F0F0F` to `#374151`)
- Accents: Purple (`#8950FA`)

---

## Accessibility

- Maintain contrast ratio of at least 4.5:1 for body text
- Primary purple (`#8950FA`) on white has ~4.6:1 contrast - use for large text or interactive elements
- For small text on light backgrounds, use `#374151` or darker
- Always provide focus states with visible outlines
- Use semantic HTML and ARIA labels

---

## Animation

```css
/* Standard transition */
transition: all 0.2s ease;

/* Hover scale effect */
.interactive:hover {
  transform: scale(1.02);
}

/* Focus ring */
.focus-ring:focus-visible {
  outline: none;
  box-shadow: 0 0 0 3px rgba(137, 80, 250, 0.4);
}
```

---

## Example: Address Display

```html
<a href="/address/0x..." class="address-link">
  <span class="font-mono text-primary">0xf3c8...cdb6</span>
  <span class="text-primary-300 text-sm">(Greeter)</span>
</a>
```

---

*Style guide generated for Gateway Block Explorer based on Gateway.fm branding.*