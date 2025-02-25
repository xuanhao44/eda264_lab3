import Database from 'better-sqlite3';
import md5 from 'md5';
import xss from 'xss';

const db = new Database('db.db');
db.exec(
	'CREATE TABLE IF NOT EXISTS Table_Users (' +
	'UID Integer Primary Key Autoincrement, ' +
	'Username TEXT NOT NULL,                ' +
	'Password TEXT NOT NULL,                ' +
	'SID TEXT)'
);

db.exec(
	'CREATE TABLE IF NOT EXISTS Table_Comments (' +
	'UID Integer Primary Key Autoincrement, ' +
	'Timestamp TEXT NOT NULL,               ' +
	'User Integer NOT NULL,                 ' +
	'Html TEXT)'
);

export function checkUserPass(username: string, password: string): { UID: number, Error?: Error } {

	if (!/^[a-zA-Z0-9_]+$/.test(username)) {
		return { UID: 0, Error: new Error("Invalid username format") };
	}

	if (!username || !password) {
		return { UID: 0, Error: new Error("Username and password cannot be empty") };
	}

	const hash = md5(password);
	// const command =
	// 	"SELECT UID FROM Table_Users WHERE Username='" + username + "' AND Password='" + hash + "'";
	// try {
	// 	const uid = db.prepare(command).get() as { UID: number };
	// 	return uid;
	// } catch (e) {
	// 	return { UID: 0, Error: e as Error }
	// }

	// use parameterized query to prevent SQL injection
	try {
		const command = db.prepare("SELECT UID FROM Table_Users WHERE Username=? AND Password=?");
		const uid = command.get(username, hash) as { UID: number };
		return uid ? uid : { UID: 0 };
	} catch (e) {
		return { UID: 0, Error: e as Error };
	}
}

export function getUserFromSessionID(sid: string): { Username: string, Error?: Error } {
	// const command = "SELECT Username FROM Table_Users WHERE SID='" + sid + "'";
	try {
		// const username = db.prepare(command).get() as { Username: string };
		// return username;

		// use parameterized query to prevent SQL injection
		const command = db.prepare("SELECT Username FROM Table_Users WHERE SID=?");
		const username = command.get(sid) as { Username: string };
		return username ? username : { Username: "" };
	} catch (e) {
		return { Username: "", Error: e as Error };
	}
}

export function getUIDFromSessionID(sid: string): number {
	// const command = "SELECT UID FROM Table_Users WHERE SID='" + sid + "'";
	// const uid = db.prepare(command).get() as { UID: number };
	// return uid.UID;

	// use parameterized query to prevent SQL injection
	try {
		const command = db.prepare("SELECT UID FROM Table_Users WHERE SID=?");
		const uid = command.get(sid) as { UID: number };
		return uid ? uid.UID : 0;
	} catch {
		return 0;
	}
}

export function addUserSessionID(uid: number, sid: string): boolean {
	// const command = "UPDATE Table_Users SET SID='" + sid + "' WHERE UID='" + uid + "'";
	try {
		// db.prepare(command).run();

		// use parameterized query to prevent SQL injection
		const command = db.prepare("UPDATE Table_Users SET SID=? WHERE UID=?");
		command.run(sid, uid);
		return true;
	} catch {
		return false;
	}
}

function isSQLInjection(input: string): boolean {
	const sqlKeywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "--", ";", "'"];
	return sqlKeywords.some(keyword => input.toUpperCase().includes(keyword));
}

export function addComment(sid: string, comment: string): { done: boolean, Error?: Error } {

	// prevent SQL injection
	if (isSQLInjection(comment)) {
		return { done: false, Error: new Error("Invalid input") };
	}

	// prevent XSS
	const safeComment = xss(comment);

	const uid = getUIDFromSessionID(sid);
	if (uid === 0) return { done: false, Error: new Error("Invalid session") };

	// const day = new Date();
	const day = new Date().toDateString();

	// const command =
	// 	"INSERT INTO Table_Comments (Timestamp, User, Html) Values('" +
	// 	day.toDateString() +
	// 	"', '" +
	// 	uid +
	// 	"', '" +
	// 	comment +
	// 	"')";
	// try {
	// 	db.exec(command);
	// 	return { done: true };
	// } catch (e) {
	// 	return { done: false, Error: e as Error };
	// }

	// use parameterized query to prevent SQL injection
	try {
		const stmt = db.prepare("INSERT INTO Table_Comments (Timestamp, User, Html) VALUES (?, ?, ?)");
		stmt.run(day, uid, safeComment);
		return { done: true };
	} catch (e) {
		return { done: false, Error: e as Error };
	}
}

// export function getComments(): [
// 	{ Timestamp: string; Username: string; Html: string }
// ] {
// 	const command =
// 		'SELECT Timestamp, Username, Html FROM ' +
// 		'Table_Comments INNER JOIN Table_Users ON ' +
// 		'Table_Comments.User=Table_Users.UID';
// 	const result = db.prepare(command).all() as [
// 		{ Timestamp: string; Username: string; Html: string }
// 	];
// 	return result;
// }

export function getComments(): { Timestamp: string; Username: string; Html: string }[] {
	try {
		const command = db.prepare(`
            SELECT Timestamp, Username, Html 
            FROM Table_Comments 
            INNER JOIN Table_Users ON Table_Comments.User = Table_Users.UID
        `);
		const results = command.all() as { Timestamp: string; Username: string; Html: string }[];

		// prevent XSS
		return results.map(comment => ({
			...comment,
			Html: xss(comment.Html)
		}));

	} catch {
		return [];
	}
}
