import { defaultValueCtx, editorViewOptionsCtx, Editor, rootCtx } from '@milkdown/core';
import { commonmark } from '@milkdown/preset-commonmark';
import { block } from '@milkdown/plugin-block';
import { clipboard } from '@milkdown/plugin-clipboard';
//import { emoji } from '@milkdown/plugin-emoji';
import { indent, indentConfig } from '@milkdown/plugin-indent';
import { listener, listenerCtx } from '@milkdown/plugin-listener';
import { math } from '@milkdown/plugin-math';
//import { nord } from '@milkdown/theme-nord';
import { prism, prismConfig } from '@milkdown/plugin-prism';

// Import PRISM languages
import css_lang from 'refractor/lang/css'
import javascript from 'refractor/lang/javascript'
import jsx from 'refractor/lang/jsx'
import markdown from 'refractor/lang/markdown'
import rust from 'refractor/lang/rust'
import tsx from 'refractor/lang/tsx'
import typescript from 'refractor/lang/typescript'

import './main.css'


function htmlToText(html: string): string {
	return html
		.replace(/<br>/g, "\n")
		.replace(/&gt;/g, ">")
		.replace(/&lt;/g, "<")
		.replace(/&amp;/g, "&")
}

function load_markdown(selector: string, editable: boolean, content?: string) {
	if (editable) {
		var underlying_element = <HTMLTextAreaElement>document.querySelector(selector + ' + textarea.default-editor')
		underlying_element.setAttribute("style", "display: none;")
	}

	Editor
		.make()
		//.config(nord)
		.config(ctx => {
			if (content) { console.log('content'); console.log(content)
				ctx.set(defaultValueCtx, content)
			}
			ctx.set(editorViewOptionsCtx, { editable: () => editable })
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
			ctx.set(rootCtx, selector)

			if (editable) {
				const listener = ctx.get(listenerCtx)
				listener.markdownUpdated((ctx, markdown, prev_markdown) => {
					if (markdown !== prev_markdown) {
						// It seems that a bug in markown places an HTML escaped
						// space character at the end sometimes instead of a
						// normal space
						if (markdown.endsWith('&#x20;\n')) {
							markdown = markdown.substring(
								0, markdown.length - 7
							) + ' \n'
						}
						underlying_element.value = markdown
					}
				})
			}
		})
		.use(block)
		.use(commonmark)
		.use(clipboard)
		//.use(emoji)
		.use(indent)
		.use(listener)
		.use(math)
		.use(prism)
		.create();
}

function load_markdown_content() {
	let elements = document.getElementsByClassName("content-markdown")
	for (let i in elements) {
		let element = elements[i]
		if (element instanceof HTMLElement ) {
			let el = <HTMLElement>element;
			el.setAttribute("style", "display: none; white-space: pre-wrap;")
			let content = htmlToText(el.innerHTML.trimStart().trimEnd());

			let id = element.id.substring("milkdown-content-".length)
			console.log("ID = " + id)
			load_markdown('#milkdown-view-' + id, false, content)
		}
	}
}


load_markdown("#editor", true, undefined)
load_markdown_content()
