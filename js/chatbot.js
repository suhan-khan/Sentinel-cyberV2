
/* =========================================================
   SENTINEL CYBER — AI ASSISTANT
   Gemini-powered chatbot using the existing ApiService
   ========================================================= */

(() => {
  'use strict';

  const state = {
    history: [],
    isSending: false,
    initialized: false
  };

  const elements = {};

  function initializeChatbot() {
    if (state.initialized) return;

    elements.launcher = document.getElementById('sentinel-chat-launcher');
    elements.window = document.getElementById('sentinel-chat-window');
    elements.close = document.getElementById('sentinel-chat-close');
    elements.clear = document.getElementById('sentinel-chat-clear');
    elements.messages = document.getElementById('sentinel-chat-messages');
    elements.input = document.getElementById('sentinel-chat-input');
    elements.send = document.getElementById('sentinel-chat-send');

    if (Object.values(elements).some(element => !element)) {
      console.error('[Sentinel AI] Chatbot HTML elements are missing.');
      return;
    }

    state.initialized = true;

    elements.launcher.addEventListener('click', openChat);
    elements.close.addEventListener('click', closeChat);
    elements.clear.addEventListener('click', clearChat);
    elements.send.addEventListener('click', sendMessage);

    elements.input.addEventListener('keydown', event => {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
      }
    });

    elements.input.addEventListener('input', autoResizeInput);

    document.querySelectorAll('.sentinel-chat-suggestion').forEach(button => {
      button.addEventListener('click', () => {
        const prompt = button.dataset.prompt;
        if (!prompt || state.isSending) return;

        elements.input.value = prompt;
        autoResizeInput();
        sendMessage();
      });
    });

    renderWelcomeMessage();

    console.log('[Sentinel AI] Chatbot interface initialized.');
  }

  function openChat() {
    elements.window.classList.remove('hidden');
    elements.launcher.setAttribute('aria-expanded', 'true');
    elements.input.focus();
    scrollToBottom();
  }

  function closeChat() {
    elements.window.classList.add('hidden');
    elements.launcher.setAttribute('aria-expanded', 'false');
  }

  function clearChat() {
    if (state.isSending) return;

    state.history = [];
    elements.messages.innerHTML = '';

    renderWelcomeMessage();

    elements.input.value = '';
    autoResizeInput();

    console.log('[Sentinel AI] Chat history cleared.');
  }

  function renderWelcomeMessage() {
    const welcome = document.createElement('div');
    welcome.className = 'sentinel-chat-welcome';

    const heading = document.createElement('h3');
    heading.textContent = 'Welcome to Sentinel AI';

    const description = document.createElement('p');
    description.textContent =
      'I can help explain your dashboard, network monitoring, Random Forest predictions and cybersecurity concepts.';

    const suggestions = document.createElement('div');
    suggestions.className = 'sentinel-chat-suggestions';

    const prompts = [
      'Explain my current dashboard status.',
      'What does the Random Forest model do?',
      'Explain the 74 network traffic features.',
      'How should I investigate a suspicious prediction?'
    ];

    prompts.forEach(prompt => {
      const button = document.createElement('button');

      button.type = 'button';
      button.className = 'sentinel-chat-suggestion';
      button.dataset.prompt = prompt;
      button.textContent = prompt;

      button.addEventListener('click', () => {
        if (state.isSending) return;

        elements.input.value = prompt;
        autoResizeInput();
        sendMessage();
      });

      suggestions.appendChild(button);
    });

    welcome.append(heading, description, suggestions);
    elements.messages.appendChild(welcome);
  }

  function addMessage(role, content) {
    const message = document.createElement('div');
    message.className = `sentinel-message ${role}`;

    const label = document.createElement('div');
    label.className = 'sentinel-message-label';
    label.textContent = role === 'user' ? 'You' : 'Sentinel AI';

    const bubble = document.createElement('div');
    bubble.className = 'sentinel-message-bubble';

    // Use textContent to prevent HTML/script injection.
    bubble.textContent = String(content);

    message.append(label, bubble);
    elements.messages.appendChild(message);

    scrollToBottom();

    return message;
  }

  function showTypingIndicator() {
    removeTypingIndicator();

    const wrapper = document.createElement('div');
    wrapper.className = 'sentinel-message assistant';
    wrapper.id = 'sentinel-typing-indicator';

    const label = document.createElement('div');
    label.className = 'sentinel-message-label';
    label.textContent = 'Sentinel AI is thinking';

    const typing = document.createElement('div');
    typing.className = 'sentinel-typing';

    for (let i = 0; i < 3; i++) {
      typing.appendChild(document.createElement('span'));
    }

    wrapper.append(label, typing);
    elements.messages.appendChild(wrapper);

    scrollToBottom();
  }

  function removeTypingIndicator() {
    document.getElementById('sentinel-typing-indicator')?.remove();
  }

  function scrollToBottom() {
    if (!elements.messages) return;

    elements.messages.scrollTop = elements.messages.scrollHeight;
  }

  function autoResizeInput() {
    if (!elements.input) return;

    elements.input.style.height = 'auto';
    elements.input.style.height =
      Math.min(elements.input.scrollHeight, 100) + 'px';
  }

  function extractAssistantResponse(data) {
    if (!data || typeof data !== 'object') return null;

    const possibleResponses = [
      data.response,
      data.reply,
      data.answer,
      data.message,
      data.text,
      data.assistant_response
    ];

    return possibleResponses.find(
      value => typeof value === 'string' && value.trim().length > 0
    ) || null;
  }

  function getFriendlyError(error) {
    const status = Number(error?.status);

    if (!navigator.onLine) {
      return 'Your internet connection appears to be offline. Please reconnect and try again.';
    }

    if (status === 429) {
      return 'The assistant is receiving too many requests. Please wait a moment and try again.';
    }

    if ([502, 503, 504].includes(status)) {
      return 'The AI service is temporarily unavailable. Please try again shortly.';
    }

    if (status === 404) {
      return 'The assistant API endpoint was not found. Please check the backend deployment.';
    }

    if (status === 422) {
      return 'The message format was rejected by the backend. Please try a shorter message.';
    }

    if (status === 500) {
      return 'The backend encountered an error while generating a response.';
    }

    return error?.message || 'Something went wrong. Please try again.';
  }

  async function sendMessage() {
    if (state.isSending) return;

    const message = elements.input.value.trim();

    if (!message) return;

    if (message.length > 2000) {
      addMessage(
        'assistant',
        'Please keep your message under 2,000 characters.'
      );
      return;
    }

    if (
      !window.ApiService ||
      typeof window.ApiService.sendAssistantMessage !== 'function'
    ) {
      addMessage(
        'assistant',
        'The assistant service is not initialized. Please refresh the page.'
      );
      return;
    }

    state.isSending = true;
    elements.send.disabled = true;

    elements.input.value = '';
    autoResizeInput();

    addMessage('user', message);
    showTypingIndicator();

    try {
      const response = await window.ApiService.sendAssistantMessage(
        message,
        state.history
      );

      removeTypingIndicator();

      const assistantReply = extractAssistantResponse(response);

      if (!assistantReply) {
        throw new Error(
          'The backend returned an unexpected response format.'
        );
      }

      addMessage('assistant', assistantReply);

      state.history.push(
        { role: 'user', content: message },
        { role: 'model', content: assistantReply }
      );

      // Keep the latest 8 messages for backend context.
      state.history = state.history.slice(-8);

    } catch (error) {
      removeTypingIndicator();

      console.error('[Sentinel AI] Request failed:', error);

      addMessage('assistant', getFriendlyError(error));

    } finally {
      state.isSending = false;
      elements.send.disabled = false;
      elements.input.focus();
    }
  }

  // Initialize after the page HTML has loaded.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeChatbot, {
      once: true
    });
  } else {
    initializeChatbot();
  }

})();
