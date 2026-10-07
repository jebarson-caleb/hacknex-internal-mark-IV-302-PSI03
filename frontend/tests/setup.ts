import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

import { beforeEach } from 'vitest';
beforeEach(() => { window.history.replaceState(null,'','/'); });
