// Microsoft logo SVG (official brand colours)
export function MicrosoftIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 21 21" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="1" y="1" width="9" height="9" fill="#F25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7FBA00" />
      <rect x="1" y="11" width="9" height="9" fill="#00A4EF" />
      <rect x="11" y="11" width="9" height="9" fill="#FFB900" />
    </svg>
  );
}

// Billions logomark — official brand mark from billions.network. Identifies
// the issuer when REQUIRE_PROOF_OF_HUMANITY=true (Path B). Harmless when
// off — the underlying flow is still Privado ID either way (RD-850 / RD-859).
export function BillionsIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 43 27" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M28.6535 0C34.3505 0 38.9688 4.61831 38.9688 10.3153V11.4776H41.038C42.1742 11.4776 43.0953 12.3987 43.0953 13.5349C43.0953 14.6711 42.1742 15.5922 41.038 15.5922H38.9688V19.3209C38.9688 23.5891 35.5088 27.0491 31.2406 27.0491H11.8547C7.58655 27.049 4.12652 23.589 4.12647 19.3209V15.5922H2.05731C0.92109 15.5922 0 14.6711 0 13.5349C0 12.3987 0.92109 11.4776 2.05731 11.4776H4.12647V10.3153C4.12648 4.61832 8.7448 1.96443e-05 14.4418 0C17.1958 0 19.6976 1.07945 21.5476 2.8381C23.3976 1.07944 25.8994 9.49645e-06 28.6535 0Z" fill="#0046FF" />
      <path d="M10.5459 10.3149C10.5459 8.16267 12.2906 6.41797 14.4428 6.41797C16.595 6.41797 18.3397 8.16267 18.3397 10.3149V18.0315C18.3397 19.4667 17.1762 20.6302 15.741 20.6302H13.1446C11.7094 20.6302 10.5459 19.4667 10.5459 18.0315V10.3149Z" fill="black" />
      <path d="M24.7578 10.3149C24.7578 8.16267 26.5025 6.41797 28.6547 6.41797C30.8069 6.41797 32.5516 8.16267 32.5516 10.3149V18.0315C32.5516 19.4667 31.3882 20.6302 29.9529 20.6302H27.3565C25.9213 20.6302 24.7578 19.4667 24.7578 18.0315V10.3149Z" fill="black" />
    </svg>
  );
}

// Privado ID logomark — the green-square icon portion of the official brand
// from privado.id (the wordmark is cropped out; we render "Privado" as text
// in the panel title).
export function PrivadoIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 87 86" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M0.90625 17.4255L0.90625 69.0478C0.90625 78.3808 8.47219 85.9468 17.8053 85.9468H69.4277C78.7607 85.9468 86.3267 78.3808 86.3267 69.0478V17.4255C86.3267 8.09243 78.7607 0.526505 69.4277 0.526505H17.8053C8.47219 0.526505 0.90625 8.09243 0.90625 17.4255Z" fill="#99FE5B" />
      <path d="M46.1919 70.4015C53.3396 70.4015 60.1944 67.5621 65.2486 62.508C70.3027 57.4539 73.1422 50.5989 73.1422 43.4513C73.1422 36.3036 70.3027 29.4488 65.2486 24.3945C60.1944 19.3404 53.3396 16.501 46.1919 16.501V70.4015Z" fill="#131313" />
      <path d="M34.2856 37.7012H23.6035V70.4013H34.2856V37.7012Z" fill="#131313" />
      <path d="M28.8924 30.4498C32.7443 30.4498 35.8669 27.3273 35.8669 23.4754C35.8669 19.6235 32.7443 16.501 28.8924 16.501C25.0405 16.501 21.918 19.6235 21.918 23.4754C21.918 27.3273 25.0405 30.4498 28.8924 30.4498Z" fill="#131313" />
    </svg>
  );
}
