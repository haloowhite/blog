// Code block copy functionality
document.addEventListener('DOMContentLoaded', function() {
    // Add copy buttons to all code blocks (div containers only, not inline code)
    // const codeBlocks = document.querySelectorAll('div.highlighter-rouge');
    //
    // codeBlocks.forEach(function(codeBlock) {
    //     // Create copy button
    //     const copyBtn = document.createElement('button');
    //     copyBtn.className = 'copy-btn';
    //     copyBtn.textContent = 'Copy';
    //     copyBtn.setAttribute('aria-label', 'Copy code to clipboard');
    //
    //     // Add copy button to code block
    //     codeBlock.appendChild(copyBtn);
    //
    //     // Add click event listener
    //     copyBtn.addEventListener('click', function() {
    //         const code = codeBlock.querySelector('code');
    //         if (code) {
    //             copyToClipboard(code.textContent, copyBtn);
    //         }
    //     });
    // });
    
    // Copy to clipboard function
    function copyToClipboard(text, button) {
        if (navigator.clipboard && window.isSecureContext) {
            // Modern clipboard API
            navigator.clipboard.writeText(text).then(function() {
                showCopySuccess(button);
            }).catch(function(err) {
                console.error('Failed to copy text: ', err);
                fallbackCopyTextToClipboard(text, button);
            });
        } else {
            // Fallback for older browsers
            fallbackCopyTextToClipboard(text, button);
        }
    }
    
    // Fallback copy method
    function fallbackCopyTextToClipboard(text, button) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        
        // Avoid scrolling to bottom
        textArea.style.top = '0';
        textArea.style.left = '0';
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                showCopySuccess(button);
            } else {
                console.error('Fallback: Copying text command was unsuccessful');
            }
        } catch (err) {
            console.error('Fallback: Oops, unable to copy', err);
        }
        
        document.body.removeChild(textArea);
    }
    
    // Show copy success feedback
    function showCopySuccess(button) {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.classList.add('copied');
        
        setTimeout(function() {
            button.textContent = originalText;
            button.classList.remove('copied');
        }, 2000);
    }
});