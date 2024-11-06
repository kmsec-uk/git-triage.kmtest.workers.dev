import { APIResponse, ErrorEvent, Repository, RepoInfo, RepoContentItem, FileItem } from "./types"
'use strict';
import { favicon, permissiveRobots, homeHTML, picoCSS } from "./html";

import * as zip from "@zip.js/zip.js";

const {
	configure,
	ZipReader,
	Uint8ArrayReader,
	Uint8ArrayWriter
} = zip;

configure({
	useWebWorkers: false,
	useCompressionStream: false
});

const github_api_headers = {
	"Accept": "application/vnd.github+json",
	"User-Agent": "kmsec.uk"
}
const currentdate = Date.now()
const cutoff = currentdate - 2592000000 // 30 days ago


const githubhosts = [
	"github.com",
	"raw.githubusercontent.com"
]

const gitlabhosts = [
	"gitlab.com"
]

/**
 * Represents an event where we determine a benign user.
 */
class VerdictError extends Error {
	constructor(message: string) {
		super(message)
	}
}

/**
 * Represents an event where we determine bad input
 */
class UserError extends Error {
	constructor(message: string) {
		super(message)
	}
}


async function getFirstEntryHash(uint8Array: Uint8Array): Promise<string[]> {

	// Creates a Uint8ArrayReader to read the array
	const zipFileReader = new Uint8ArrayReader(uint8Array);
	// create writer instance
	const thisWriter = new Uint8ArrayWriter()

	// Creates a ZipReader object reading the zip content via `zipFileReader`,
	// retrieves metadata (name, dates, etc.) of the first entry, retrieves its
	// content via `helloWorldWriter`, and closes the reader.
	const zipReader = new ZipReader(zipFileReader);
	const firstEntry = (await zipReader.getEntries()).shift();
	let digest = ""
	let name = ""
	if ((typeof firstEntry !== "undefined")) {
		name = firstEntry.filename
		const content = await firstEntry.getData!(thisWriter);
		digest = await sha256(content)
	}
	await zipReader.close();
	return [name, digest];
}
/**
 * Get the SHA256 hash of some content using the Web Crypto API
 * [https://developers.cloudflare.com/workers/runtime-apis/web-crypto/](Cloudflare docs)
 * @param arr uint8array of the content
 * @returns a promise resolving to a string (the hash)
 */
async function sha256(arr: Uint8Array): Promise<string> {
	const myDigest = await crypto.subtle.digest(
		{
			name: 'SHA-256',
		},
		arr);

	return [...new Uint8Array(myDigest)].map(b => b.toString(16).padStart(2, '0'))
		.join('');
}

/**
 * Event Represents a Triage event. All triage starts with a URL.
 */
class Event {
	verdict: string
	url: string;
	username: string;
	repositories: RepoInfo[]
	platform: string
	user_created: string
	iocs: string[]

	constructor(url: string) {
		this.verdict = "undetermined"
		this.url = url
		this.username = ""
		this.repositories = []
		this.platform = ""
		this.user_created = ""
		this.iocs = []
	}

	/**
	 * The entrypoint and wrapper function for analysis
	 * @returns Promise<Response>
	 */
	async reviewURL(): Promise<Response> {
		try {
			// check the URL and see if we can triage it.
			this.parseURL()
			// check the user on Github
			await this.checkUserGithub()
			// for each repo, scrape the API for info on this repo.
			for await (const repo of this.repositories) {
				const index = this.repositories.indexOf(repo)
				this.repositories[index] = await this.repoGHTriage(repo)
			}

		} catch (error: unknown) {
			if (error instanceof VerdictError) {
				return new Response(JSON.stringify(this.toBenignVerdict(error.message)), {
					status: 200,
					headers: {
						"Content-Type": "application/json"
					}
				})
			} else if (error instanceof Error) {
				return new Response(JSON.stringify(this.toError(error.message)), {
					status: 500,
					headers: {
						"Content-Type": "application/json"
					}
				})
			}
		}

		return new Response(JSON.stringify(this.toDict()), {
			headers: {
				"Content-Type": "application/json"
			}
		})
	}

	/**
	 * Parses a URL and determines if we can triage it.
	 *
	 * @returns undefined 
	 */
	parseURL(): undefined {

		const objurl = new URL(this.url)

		if (githubhosts.includes(objurl.host)) {
			this.platform = "GitHub"
		} else {
			throw new Error("unsupported host, only GitHub is supported for now")
		}
		const username = objurl.pathname.split("/")[1]
		this.username = username
		return
	}

	/**
	 * Updates `this` properties and gathers some initial information about repositories.
	 * @returns Promise<undefined>
	 */
	async checkUserGithub(): Promise<void> {
		const userresp = await fetch("https://api.github.com/users/" + this.username, {
			headers: github_api_headers
		})
		if (!userresp.ok) {
			if (userresp.status === 404) {
				throw new Error("username not found")
			}
			throw new Error(`error retrieving user data from github: ${await userresp.text()}`)
		}
		const userrspJson: any = await userresp.json()

		const user_created = Date.parse(userrspJson['created_at'])

		// if (user_created < cutoff) {
		// 	throw new VerdictError(`Users older than 30 days are not processed as this does not match known TTPs. User created at ${userrspJson['created_at']}`)
		// }

		this.user_created = new Date(user_created).toISOString()


		// Get repos
		var reporesp = await fetch(userrspJson['repos_url'], {
			headers: github_api_headers
		})

		if (!reporesp.ok) {
			throw new Error(`error retrieving user data from github: ${await reporesp.text()}`)
		}
		const reporspJson = <Repository[]>(await reporesp.json())

		if (reporspJson.length === 0) {
			throw new VerdictError(`${this.username} has no repos`)
		}

		this.repositories = reporspJson.map((repo: Repository) => <RepoInfo>{
			"name": repo.name,
			"description": repo.description,
			"created": repo.created_at,
			"_apiurl": repo.url,
			"contents": [],
			"commit_emails": [],
		})
		return
	}


	/**
	 * Returns information on the contents of a repository, including
	 * commit authors and repo contents.
	 * We only check the root directory of the repo for contents.
	 * If a repository doesn't meet threshold for suspicion, the verdict is
	 * benign and no further analysis is done.
	 * @param repo the repository to triage
	 * @returns 
	 */
	async repoGHTriage(repo: RepoInfo): Promise<RepoInfo> {

		repo.commit_emails = await this.getRepoCommitsGH(repo._apiurl!)

		const contentsresp = await fetch(repo._apiurl! + "/contents", {
			headers: github_api_headers
		})
		if (!contentsresp.ok) {
			console.log(contentsresp.status)
			if (contentsresp.status === 404) {
				// This repo is empty
				repo.verdict = "benign"
				return repo
			}
			throw new Error(`error retrieving contents for repo ${repo.name}: ${await contentsresp.text()}`)
		}
		const contentsJson = <any[]>(await contentsresp.json())
		let countfiles = 0
		let countcompressed = 0

		for (const obj of contentsJson) {
			countfiles++
			if (/.*\.(zip|tar)$/.test(obj['name'])) {
				countcompressed++
			}
		}
		// if there are no files, no zips, or the zips don't 
		// make up at least 50% of the repo, return
		// console.log(`count: ${countfiles}, compressed: ${countcompressed}, ratio: ${countcompressed / countfiles}`)
		if (countfiles === 0 || countcompressed === 0 || countcompressed / countfiles < 0.5) {
			repo.contents = contentsJson.map((item) =><RepoContentItem>{
				"name": item.name,
				"size" : item.size
			})
			repo.verdict = "undetermined"
			return repo
		}
		repo.verdict = "suspicious"
		this.verdict = "suspicious"
		repo.contents = await Promise.all(contentsJson.map(async (item): Promise<RepoContentItem> => {
			return await this.retrieveGHObject(item)
		}))
		return repo
	}
	/**
	 * Retrieves a file and unzips it if it is under 350000 bytes / 3.5MB,
	 * otherwise just return the object as-is
	 * @param item <FileItem> a content Object containing information about an object
	 * @returns a promise resolving to an Object 
	 */
	async retrieveGHObject(item: FileItem): Promise<RepoContentItem> {
		let first_content_name, first_content_sha256, zip_sha256
		// console.log(item.size, item.name)
		if (item.size < 3500000 && /.*\.(zip|tar)$/.test(item.name)) {
			// console.log(`retrieiving ${item.download_url}`)
			const resp = await fetch(new URL(item.download_url))

			if (!resp.ok) {
				throw new Error(`error retrieving ${item.name}: ${await resp.text()}`)					
			}

			const respuint8array: Uint8Array = new Uint8Array(await resp.arrayBuffer())
			zip_sha256 = await sha256(respuint8array)
			const zipcontents = await getFirstEntryHash(respuint8array)
			first_content_name = zipcontents[0]
			first_content_sha256 = zipcontents[1]
		}

		return {
			"name": item.name,
			"size": item.size,
			"sha256": zip_sha256 ? zip_sha256 : "",
			"first_content_name": first_content_name,
			"first_content_sha256": first_content_sha256
		}
	}

	/**
	 * Retrieves all distinct commit emails for a repo
	 * @param repourl
	 * @returns a promise resolving to an array of distinct commit authors
	 */
	async getRepoCommitsGH(repourl: string): Promise<string[]> {

		const commitemails: string[] = []

		const commitreq = await fetch(repourl + '/commits', {
			headers: github_api_headers
		})

		if (!commitreq.ok) {
			if (commitreq.status > 400 && commitreq.status < 499) {
				return commitemails
			}

			throw new Error(`error retrieving commit data from github: ${await commitreq.text()}`)
		}

		const commitdata = <any[]>(await commitreq.json())

		commitdata.forEach(commit => {
			const commitemailAuthor = commit['commit']['author']['email']
			const commitemailCommitter = commit['commit']['committer']['email']
			// console.log(commitemailAuthor, commitemailCommitter)
			if (commitemailAuthor && !commitemails.includes(commitemailAuthor)) {
				commitemails.push(commitemailAuthor)
			}
			if (commitemailCommitter && !commitemails.includes(commitemailCommitter) && commitemailCommitter !== "noreply@github.com") {
				commitemails.push(commitemailCommitter)
			}
		})
		return commitemails
	}
	toDict(): APIResponse {
		return {
			"verdict" : this.verdict,
			"url": this.url,
			"username": this.username,
			"repositories": this.repositories,
			"platform": this.platform,
			"user_created": this.user_created

		}
	}

	toError(errormsg: string): ErrorEvent {
		return {
			"url": this.url,
			"error": errormsg
		}
	}
	toBenignVerdict(verdict: string) {
		return {
			"verdict": "benign",
			"url": this.url,
			"username": this.username,
			"reason": verdict
		}
	}

}


async function router(request: Request, ctx: ExecutionContext): Promise<Response> {
	if (request.method !== "GET") {
		return new Response(JSON.stringify(new Event("").toError("only GET requests are supported")), {
			headers: {
				"Content-Type": "application/json"
			}
		})
	}
	const url = new URL(request.url)
	const host = url.host
	const [path, params] = [url.pathname, url.searchParams]

	switch (path) {
		case '/':
			var urlParam = params.get('url')
			return new Response(homeHTML(host, urlParam), {
				status: 200,
				headers: {
					"Content-Type": "text/html"
				}
			})
		case '/picocss.min.css':
			return new Response(picoCSS, {
				status: 200,
				headers: {
					"Content-Type": "text/css",
					"Cache-Control": "max-age=31536000, public"
				}
			})
		case "/favicon.png":
			return new Response(favicon(), {
				headers: {
					"Content-Type": "image/png"
				}
			})


		case '/robots.txt':
			return new Response(permissiveRobots, {
				status: 200,
				headers: {
					"Content-Type": "text/plain"
				}
			})
		case "/api":
		case "/api/":

			let requrl = params.get("url")
			if (!requrl) {
				return new Response(JSON.stringify(new Event("").toError("a url parameter must be provided")), {
					status: 400,
					headers: {
						"Content-Type": "application/json"
					}
				})
			}
			if (!/^https?:\/\/.*/.test(requrl)) {
				requrl = 'https://' + requrl

			}

			var event = new Event(requrl)

			return await event.reviewURL()

		default:
			return new Response(JSON.stringify({ "error": "404 not found" }), {
				status: 404,
				statusText: "404 not found",
				headers: {
					"Content-Type": "application/json"
				}
			})
	}
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		return await router(request, ctx)
	},
};
