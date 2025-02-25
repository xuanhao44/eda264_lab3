import { getUserFromSessionID } from '$lib/db';
import { error, redirect } from '@sveltejs/kit';
import { fileTypeFromBuffer } from 'file-type';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'path';

/** @type {import('./$types').PageServerLoad} */
export async function load({ cookies }) {
	const sessionid = cookies.get('sessionid');
	if (sessionid === undefined) redirect(307, '/');
	const user = getUserFromSessionID(sessionid);
	if (user !== undefined) {
		if (user.Error === undefined)
			return { user, sessionid };
		else {
			cookies.delete('sessionid', { path: '/' });
			error(500, user.Error.message);
		}
	} else {
		cookies.delete('sessionid', { path: '/' });
		redirect(307, '/');
	}
}

/** @type {import('./$types').Actions} */
export const actions = {
	upload: async ({ request }) => {
		const data = await request.formData();
		const formData = Object.fromEntries(data);

		if (
			!(formData.fileToUpload as File).name ||
			(formData.fileToUpload as File).name === 'undefined'
		) {
			console.log('Upload failed: No file provided');
			return { success: false, message: 'You must provide a file to upload' };
		}

		const p = data.get('path');
		const { fileToUpload } = formData as { fileToUpload: File };
		const buffer = Buffer.from(await fileToUpload.arrayBuffer());
		const fileType = await fileTypeFromBuffer(buffer);

		if (!fileType) {
			console.log('Upload failed: Unsupported file type');
			return { success: false, message: 'Unsupported file type' };
		}

		const safePath = path.normalize(`uploads/${p}${path.extname(fileToUpload.name)}`);
		if (!safePath.startsWith('uploads/')) {
			console.log('Upload failed: Unsafe path');
			return { success: false, message: 'Unsafe path' };
		}

		if (!existsSync(path.dirname(`static/${safePath}`))) {
			mkdirSync(path.dirname(`static/${safePath}`), { recursive: true });
		}

		writeFileSync(`static/${safePath}`, buffer);

		console.log(`Upload successful: ${safePath}`);
		return { success: true, path: safePath };
	}
};