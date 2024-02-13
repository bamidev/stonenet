import { defaultValueCtx, Editor, rootCtx } from '@milkdown/core';
import { commonmark } from '@milkdown/preset-commonmark';
import { block } from '@milkdown/plugin-block';
import { clipboard } from '@milkdown/plugin-clipboard';
import { indent, indentConfig } from '@milkdown/plugin-indent';
import { math } from '@milkdown/plugin-math';
import { prism, prismConfig } from '@milkdown/plugin-prism';

// Import PRISM languages
import css_lang from 'refractor/lang/css'
import javascript from 'refractor/lang/javascript'
import jsx from 'refractor/lang/jsx'
import markdown from 'refractor/lang/markdown'
import rust from 'refractor/lang/rust'
import tsx from 'refractor/lang/tsx'
import typescript from 'refractor/lang/typescript'


// Hide the actual form element
let elements = document.getElementsByClassName("no-editor")
for (let i in elements) {
	let e = elements[i]
	console.log(elements)
	if (e instanceof Element) { e.setAttribute("style", "display: none;") }
}

Editor
	.make()
	.config(ctx => {
		ctx.set(indentConfig.key, {
			type: 'tab',
			size: 4,
		})
		ctx.set(prismConfig.key, {
			configureRefractor: (refractor) => {
				refractor.register(css_lang)
				refractor.register(javascript)
				refractor.register(jsx)
				refractor.register(markdown)
				refractor.register(rust)
				refractor.register(tsx)
				refractor.register(typescript)
			  },
		})
		ctx.set(rootCtx, '.editor')
	})
	.use(block)
	.use(commonmark)
	.use(clipboard)
	.use(indent)
	.use(math)
	.use(prism)
	.create();
