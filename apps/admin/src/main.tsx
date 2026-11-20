import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/tokens.css';
import './styles/layout.css';
import './styles/components.css';
import './styles/ds.css';
import './styles/window.css';
import { App } from './App';

const container = document.getElementById('root');
if (!container) {
  throw new Error('Root mount element #root not found in index.html');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
