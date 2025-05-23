// FrontScripting.js
const userInputElement = document.getElementById('user-input');
const chatHistory = document.getElementById('chat-history');
const sendBtn = document.getElementById('send-btn');

// Send message function
async function sendMessage() {
    const userInput = userInputElement.value.trim();
    if (!userInput) return;

    // Display user message bubble on the right
    chatHistory.innerHTML += `<div class="user-bubble">${userInput}</div>`;

    try {
        const response = await fetch("http://localhost:5005/webhooks/rest/webhook", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sender: "user123", message: userInput }),
        });

        const data = await response.json();

        if (data.length === 0) {
            chatHistory.innerHTML += `<div class="bot-bubble">Sorry, I didn't understand that.</div>`;
        } else {
            data.forEach(msg => {
                if (msg.text) {
                    chatHistory.innerHTML += `<div class="bot-bubble">${msg.text}</div>`;
                }
            });
        }
    } catch (error) {
        console.error('Error:', error);
        chatHistory.innerHTML += `<div class="bot-bubble">⚠️ Sorry, I couldn’t connect to the server.</div>`;
    }

    // Scroll to bottom and clear input
    chatHistory.scrollTop = chatHistory.scrollHeight;
    userInputElement.value = '';
}


// Trigger send on button click
sendBtn.addEventListener('click', sendMessage);

// Trigger send on Enter key
userInputElement.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});
