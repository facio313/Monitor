import { useEffect, useState } from 'react';

export interface ResponsivePageSizes {
  desktop: number;
  tablet: number;
  phone: number;
  narrowPhone: number;
}

export function responsivePageSize(width: number, sizes: ResponsivePageSizes): number {
  if (width <= 360) return sizes.narrowPhone;
  if (width <= 640) return sizes.phone;
  if (width <= 1024) return sizes.tablet;
  return sizes.desktop;
}

export function useResponsivePageSize(sizes: ResponsivePageSizes): number {
  const [pageSize, setPageSize] = useState(() => typeof window === 'undefined'
    ? sizes.desktop
    : responsivePageSize(window.innerWidth, sizes));

  useEffect(() => {
    const update = () => setPageSize(responsivePageSize(window.innerWidth, sizes));
    window.addEventListener('resize', update, { passive: true });
    window.addEventListener('orientationchange', update, { passive: true });
    update();
    return () => {
      window.removeEventListener('resize', update);
      window.removeEventListener('orientationchange', update);
    };
  }, [sizes.desktop, sizes.narrowPhone, sizes.phone, sizes.tablet]);

  return pageSize;
}
