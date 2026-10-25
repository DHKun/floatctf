import type { WebAccount } from "@floatctf/sdk";
import {
	PersonAddIcon,
	PersonIcon,
	SignOutIcon,
} from "@primer/octicons-react";
import { ActionList, ActionMenu, Avatar, Dialog, useConfirm } from "@primer/react";
import { useState } from "react";

import { client } from "@/api";
import { useAppNavigate } from "@/navigation";
import { mutateSession } from "@/session";
import { useSessionStore } from "@/stores/SessionStore";

import { formatApiError } from "./apiErrorMessage";

/** 头像：只用平台上传的同源图片；没有头像时显示首字母（Primer Avatar 需要 src，这里自绘回退）。 */
function AccountAvatar({ account, size = 20 }: { account: Pick<WebAccount, "avatar" | "nickname" | "username">; size?: number }) {
	if (account.avatar?.startsWith("/public/")) {
		return <Avatar src={account.avatar} size={size} alt="" />;
	}
	const initial = (account.nickname || account.username).trim().charAt(0).toUpperCase() || "?";
	return (
		<span
			aria-hidden="true"
			className="d-inline-flex flex-items-center flex-justify-center circle color-bg-subtle color-fg-default text-bold"
			style={{ width: size, height: size, fontSize: Math.round(size * 0.45) }}
		>
			{initial}
		</span>
	);
}

/**
 * 主站账号菜单（统一 Cookie 会话部署）：
 * - 本浏览器中真实有效的账号（服务端判定）之间切换；
 * - 添加账号（保留当前已登录的账号）；
 * - 退出当前账号 / 退出本浏览器全部账号 —— 只撤销 FloatCTF 身份会话，**不**通知第三方应用。
 *
 * 所有操作都等服务端确认后才更新界面；失败弹出「操作未完成」。
 */
export function AccountMenu() {
	const status = useSessionStore((s) => s.status);
	const navigate = useAppNavigate();
	const confirm = useConfirm();
	const [error, setError] = useState<{ title: string; message: string } | null>(null);
	const [pending, setPending] = useState(false);

	if (!status?.user) return null;
	const current = status.user;
	const others = status.accounts.filter((a) => !a.active);

	const run = async (title: string, action: () => Promise<void>) => {
		if (pending) return;
		setPending(true);
		try {
			await action();
			setError(null);
		} catch (e) {
			setError({ title, message: formatApiError(e) });
		} finally {
			setPending(false);
		}
	};

	const switchTo = (account: WebAccount) =>
		run("切换账号未完成", async () => {
			await mutateSession((csrf) => client.service.webSession.select(account.id, csrf));
			navigate({ to: "/service/top" });
		});

	const signOutCurrent = () =>
		run("退出未完成", async () => {
			await mutateSession((csrf) => client.service.webSession.logout("account", null, csrf));
			navigate({ to: "/" });
		});

	const signOutBrowser = async () => {
		const ok = await confirm({
			title: "退出本浏览器中的全部账号？",
			content: `将退出本浏览器中已登录的 ${status.accounts.length} 个 FloatCTF 账号。已经登录的第三方应用（如 LearnOS）不受影响。`,
			confirmButtonContent: "全部退出",
			confirmButtonType: "danger",
		});
		if (!ok) return;
		await run("退出未完成", async () => {
			await mutateSession((csrf) => client.service.webSession.logout("browser", null, csrf));
			navigate({ to: "/" });
		});
	};

	return (
		<>
			<ActionMenu>
				<ActionMenu.Button
					aria-label={`账号菜单：${current.nickname}（@${current.username}）`}
					leadingVisual={() => <AccountAvatar account={current} />}
				>
					{current.nickname}
				</ActionMenu.Button>
				<ActionMenu.Overlay width="medium" align="end">
					<ActionList>
						<ActionList.Group>
							<ActionList.GroupHeading>当前账号</ActionList.GroupHeading>
							<ActionList.Item onSelect={() => navigate({ to: "/service/profile" })}>
								<ActionList.LeadingVisual>
									<AccountAvatar account={current} />
								</ActionList.LeadingVisual>
								{current.nickname}
								<ActionList.Description variant="block">@{current.username} · 个人资料</ActionList.Description>
							</ActionList.Item>
						</ActionList.Group>
						{others.length > 0 && (
							<ActionList.Group>
								<ActionList.GroupHeading>切换到本浏览器中的其他账号</ActionList.GroupHeading>
								{others.map((account) => (
									<ActionList.Item key={account.id} onSelect={() => void switchTo(account)} disabled={pending}>
										<ActionList.LeadingVisual>
											<AccountAvatar account={account} />
										</ActionList.LeadingVisual>
										{account.nickname}
										<ActionList.Description variant="block">@{account.username}</ActionList.Description>
									</ActionList.Item>
								))}
							</ActionList.Group>
						)}
						<ActionList.Divider />
						{status.accounts.length < status.max_accounts && (
							<ActionList.Item onSelect={() => navigate({ to: "/", search: { add: true } })}>
								<ActionList.LeadingVisual>
									<PersonAddIcon />
								</ActionList.LeadingVisual>
								添加账号
							</ActionList.Item>
						)}
						<ActionList.Item onSelect={() => void signOutCurrent()} disabled={pending}>
							<ActionList.LeadingVisual>
								<SignOutIcon />
							</ActionList.LeadingVisual>
							退出当前账号
							<ActionList.Description variant="block">只退出 FloatCTF，不影响已登录的第三方应用</ActionList.Description>
						</ActionList.Item>
						{status.accounts.length > 1 && (
							<ActionList.Item variant="danger" onSelect={() => void signOutBrowser()} disabled={pending}>
								<ActionList.LeadingVisual>
									<PersonIcon />
								</ActionList.LeadingVisual>
								退出本浏览器中的全部账号
							</ActionList.Item>
						)}
					</ActionList>
				</ActionMenu.Overlay>
			</ActionMenu>
			{error && (
				<Dialog
					title={error.title}
					onClose={() => setError(null)}
					footerButtons={[{ content: "关闭", onClick: () => setError(null) }]}
				>
					<p>服务端没有确认这次操作（{error.message}），当前登录状态没有改变。请稍后重试。</p>
				</Dialog>
			)}
		</>
	);
}
