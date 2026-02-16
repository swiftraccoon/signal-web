import { get, put, STORES } from '../storage/indexeddb';

interface OnboardingStep {
  targetSelector: string;
  title: string;
  description: string;
}

const STEPS: OnboardingStep[] = [
  {
    targetSelector: '#contacts-list',
    title: 'Your Contacts',
    description: 'Conversations appear here as you start chatting with people.',
  },
  {
    targetSelector: '#user-search',
    title: 'Search',
    description: 'Find users to start an encrypted conversation.',
  },
  {
    targetSelector: '#chat-area',
    title: 'Messages',
    description: 'End-to-end encrypted conversations show up here.',
  },
];

let overlay: HTMLDivElement | null = null;
let tooltip: HTMLDivElement | null = null;

function createOverlay(): HTMLDivElement {
  const el = document.createElement('div');
  el.className = 'onboarding-overlay';
  document.body.appendChild(el);
  return el;
}

function createTooltip(): HTMLDivElement {
  const el = document.createElement('div');
  el.className = 'onboarding-tooltip';
  document.body.appendChild(el);
  return el;
}

function positionTooltip(tooltipEl: HTMLDivElement, targetSelector: string): void {
  const target = document.querySelector(targetSelector);
  if (!target) {
    centerTooltip(tooltipEl);
    return;
  }

  const rect = target.getBoundingClientRect();
  const tooltipRect = tooltipEl.getBoundingClientRect();
  const vh = window.innerHeight;

  let left = rect.left + rect.width / 2 - tooltipRect.width / 2;
  if (left < 8) left = 8;
  if (left + tooltipRect.width > window.innerWidth - 8) {
    left = window.innerWidth - tooltipRect.width - 8;
  }

  // Try below, then above, then center vertically on the target
  let top = rect.bottom + 12;
  if (top + tooltipRect.height > vh - 8) {
    top = rect.top - tooltipRect.height - 12;
  }
  if (top < 8) {
    top = rect.top + rect.height / 2 - tooltipRect.height / 2;
    top = Math.max(8, Math.min(top, vh - tooltipRect.height - 8));
  }

  tooltipEl.style.top = `${top}px`;
  tooltipEl.style.left = `${left}px`;
  tooltipEl.style.transform = 'none';
}

function centerTooltip(tooltipEl: HTMLDivElement): void {
  tooltipEl.style.top = '50%';
  tooltipEl.style.left = '50%';
  tooltipEl.style.transform = 'translate(-50%, -50%)';
}

function buildTooltipContent(
  stepIndex: number,
  onNext: () => void,
  onSkip: () => void
): DocumentFragment {
  const step = STEPS[stepIndex]!;
  const isLast = stepIndex === STEPS.length - 1;
  const frag = document.createDocumentFragment();

  const stepCounter = document.createElement('div');
  stepCounter.className = 'onboarding-step';
  stepCounter.textContent = `Step ${stepIndex + 1} of ${STEPS.length}`;
  frag.appendChild(stepCounter);

  const title = document.createElement('h4');
  title.className = 'onboarding-title';
  title.textContent = step.title;
  frag.appendChild(title);

  const desc = document.createElement('p');
  desc.className = 'onboarding-desc';
  desc.textContent = step.description;
  frag.appendChild(desc);

  const actions = document.createElement('div');
  actions.className = 'onboarding-actions';

  const skipBtn = document.createElement('button');
  skipBtn.className = 'onboarding-btn onboarding-btn-skip';
  skipBtn.textContent = 'Skip';
  skipBtn.addEventListener('click', onSkip);
  actions.appendChild(skipBtn);

  const nextBtn = document.createElement('button');
  nextBtn.className = 'onboarding-btn onboarding-btn-next';
  nextBtn.textContent = isLast ? 'Done' : 'Next';
  nextBtn.addEventListener('click', onNext);
  actions.appendChild(nextBtn);

  frag.appendChild(actions);
  return frag;
}

function renderStep(stepIndex: number, onNext: () => void, onSkip: () => void): void {
  if (!tooltip) return;
  const step = STEPS[stepIndex];
  if (!step) return;

  // Clear previous content
  while (tooltip.firstChild) {
    tooltip.removeChild(tooltip.firstChild);
  }

  tooltip.appendChild(buildTooltipContent(stepIndex, onNext, onSkip));

  // Position after content is rendered so we can measure
  requestAnimationFrame(() => {
    positionTooltip(tooltip!, step.targetSelector);
  });
}

async function markCompleted(): Promise<void> {
  await put(STORES.ONBOARDING, 'completed', true);
}

function cleanup(): void {
  if (overlay) {
    overlay.remove();
    overlay = null;
  }
  if (tooltip) {
    tooltip.remove();
    tooltip = null;
  }
}

function runTour(): Promise<void> {
  return new Promise<void>((resolve) => {
    overlay = createOverlay();
    tooltip = createTooltip();

    let currentStep = 0;

    function finish(): void {
      cleanup();
      markCompleted().then(resolve).catch(() => resolve());
    }

    function advance(): void {
      currentStep++;
      if (currentStep >= STEPS.length) {
        finish();
      } else {
        renderStep(currentStep, advance, finish);
      }
    }

    renderStep(currentStep, advance, finish);
  });
}

async function showOnboardingIfNew(): Promise<void> {
  try {
    const completed = await get(STORES.ONBOARDING, 'completed');
    if (completed) return;
    await runTour();
  } catch (err) {
    console.error('Onboarding error:', err);
    cleanup();
  }
}

export { showOnboardingIfNew };
