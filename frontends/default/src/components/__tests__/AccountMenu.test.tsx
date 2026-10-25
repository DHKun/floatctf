// @vitest-environment jsdom
import type { WebSessionStatus } from "@floatctf/sdk";
import { BaseStyles, ThemeProvider } from "@primer/react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useSessionStore } from "@/stores/SessionStore";
import { AccountMenu } from "../AccountMenu";

/**
 * 主站账号菜单：只列服务端给出的本浏览器有效账号；切换 / 退出都等服务端确认；
 * 失败如实提示且登录状态不变。
 */

const { navigate, webSession } = vi.hoisted(() => ({
	navigate: vi.fn(),
	webSession: { select: vi.fn(), logout: vi.fn(), status: vi.fn() },
}));

vi.mock("@/navigation", () => ({ useAppNavigate: () => navigate }));
vi.mock("@/api", () => ({ client: { service: { webSession } } }));
vi.mock("@/api/client", () => ({ client: { service: { webSession } } }));
vi.mock("@/integrations/tanstack-query/root-provider", () => ({
	getContext: () => ({ queryClient: { clear: vi.fn() } }),
}));

const alice = { id: "u-a", username: "alice", nickname: "Alice 同学" };
const bob = { id: "u-b", username: "bob", nickname: "Bob 同学" };

function status(user = alice): WebSessionStatus {
	return {
		mode: "cookie",
		authenticated: true,
		user,
		csrf_token: "csrf",
		accounts: [
			{ id: "s-a", user_id: alice.id, username: "alice", nickname: alice.nickname, active: user.id === alice.id },
			{ id: "s-b", user_id: bob.id, username: "bob", nickname: bob.nickname, active: user.id === bob.id },
		],
		auto_restore: false,
		max_accounts: 5,
		global_logout: false,
	};
}

async function setup() {
	useSessionStore.getState().setStatus(status());
	render(
		<ThemeProvider>
			<BaseStyles>
				<AccountMenu />
			</BaseStyles>
		</ThemeProvider>,
	);
	fireEvent.click(screen.getByRole("button", { name: /账号菜单/ }));
	return { useSessionStore };
}

beforeEach(() => {
	globalThis.ResizeObserver ??= class {
		observe() {}
		unobserve() {}
		disconnect() {}
	} as unknown as typeof ResizeObserver;
	window.matchMedia = ((query: string) => ({
		matches: false,
		media: query,
		onchange: null,
		addListener: () => undefined,
		removeListener: () => undefined,
		addEventListener: () => undefined,
		removeEventListener: () => undefined,
		dispatchEvent: () => false,
	})) as unknown as typeof window.matchMedia;
	const data = new Map<string, string>();
	Object.defineProperty(window, "localStorage", {
		configurable: true,
		value: {
			getItem: (k: string) => data.get(k) ?? null,
			setItem: (k: string, v: string) => void data.set(k, v),
			removeItem: (k: string) => void data.delete(k),
			clear: () => data.clear(),
			key: () => null,
			length: 0,
		},
	});
	navigate.mockReset();
	for (const fn of Object.values(webSession)) fn.mockReset();
});

afterEach(() => cleanup());

describe("AccountMenu", () => {
	it("switches to another account in this browser after the server confirms", async () => {
		webSession.select.mockResolvedValue(status(bob));
		const { useSessionStore } = await setup();
		fireEvent.click(await screen.findByText("Bob 同学"));
		await waitFor(() => expect(webSession.select).toHaveBeenCalledWith("s-b", "csrf"));
		await waitFor(() => expect(navigate).toHaveBeenCalledWith({ to: "/service/top" }));
		expect(useSessionStore.getState().status?.user?.id).toBe(bob.id);
	});

	it("keeps the user signed in and explains when sign-out fails", async () => {
		webSession.logout.mockRejectedValue({ httpStatus: 500, response: { status: 500, data: {} } });
		const { useSessionStore } = await setup();
		fireEvent.click(await screen.findByText("退出当前账号"));
		expect(await screen.findByText("退出未完成")).toBeTruthy();
		expect(navigate).not.toHaveBeenCalled();
		expect(useSessionStore.getState().status?.authenticated).toBe(true);
	});

	it("offers adding an account and signing out of every account in this browser", async () => {
		await setup();
		expect(await screen.findByText("添加账号")).toBeTruthy();
		expect(screen.getByText("退出本浏览器中的全部账号")).toBeTruthy();
		expect(screen.getByText("只退出 FloatCTF，不影响已登录的第三方应用")).toBeTruthy();
	});
});
