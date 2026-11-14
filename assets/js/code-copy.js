// Adds a copy button to every fenced code block.
// Inline code also carries .highlighter-rouge, so only the div form is matched.
(function () {
    function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }

        // Fallback for http:// and older browsers.
        return new Promise(function (resolve, reject) {
            var area = document.createElement('textarea');
            area.value = text;
            area.setAttribute('readonly', '');
            area.style.position = 'fixed';
            area.style.top = '0';
            area.style.left = '0';
            area.style.opacity = '0';
            document.body.appendChild(area);
            area.select();
            try {
                document.execCommand('copy') ? resolve() : reject(new Error('copy command failed'));
            } catch (err) {
                reject(err);
            } finally {
                document.body.removeChild(area);
            }
        });
    }

    function addButton(block) {
        var code = block.querySelector('pre code');
        if (!code) return;

        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'code-copy';
        button.textContent = 'Copy';

        var timer;
        button.addEventListener('click', function () {
            copyText(code.textContent).then(function () {
                button.textContent = 'Copied';
            }, function () {
                button.textContent = 'Failed';
            }).then(function () {
                clearTimeout(timer);
                timer = setTimeout(function () {
                    button.textContent = 'Copy';
                }, 1600);
            });
        });

        block.appendChild(button);
    }

    // Fences in a language Rouge doesn't know render as a bare <pre>; give
    // them the same wrapper so the button has something to anchor to.
    function wrapBare(pre) {
        var wrapper = document.createElement('div');
        wrapper.className = 'highlighter-rouge';
        pre.parentNode.insertBefore(wrapper, pre);
        wrapper.appendChild(pre);
    }

    function init() {
        document.querySelectorAll('.prose > pre').forEach(wrapBare);
        document.querySelectorAll('div.highlighter-rouge').forEach(addButton);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
