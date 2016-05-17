(function() {
	var elements = document.getElementsByTagName('script')
	for (var i = 0; i < elements.length; i++) {
		var element = elements[i];
		if (element.type.indexOf('math/tex') !== -1) {
			// Extract math markdown
			var textToRender = element.innerText || element.textContent;
			// Create span for KaTeX
			var katexElement = document.createElement('span');
			// Support inline and display math
			if (element.type.indexOf('mode=display') !== -1) {
				katexElement.className += "math-display";
				textToRender = '\\displaystyle {' + textToRender + '}';
			} else {
				katexElement.className += "math-inline";
			}
			// Render the TeX and insert it into the document.
			katex.render(textToRender, katexElement);
			element.parentNode.insertBefore(katexElement, element);
		}
	}
})();
