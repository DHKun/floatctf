import {
	Avatar,
	Button,
	FormControl,
	Heading,
	Link,
	TextInput,
} from "@primer/react";
import { useMutation } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useReactive, useTitle } from "ahooks";
import { useEffect, useRef } from "react";

import { client, serviceApi } from "@/api";
import { useMsgInlineBanner } from "@/components";
import { AppLink } from "@/navigation";
import { ServiceRouteGuardWithRedirect } from "@/routes/service/route";
import { isCookieMode, mutateSession } from "@/session";
import { useAuthStore } from "@/stores/AuthStore";
import { getLearnOSUrl } from "@/util";

export const Route = createFileRoute("/")({
	component: App,
	loader: ServiceRouteGuardWithRedirect,
});

function App() {
	useTitle("Login | FloatCTF");
	const banner = useMsgInlineBanner();

	const form = useReactive({
		username: "",
		password: "",
		buttonMessage: "Sign in",
		buttonDisabled: false,
	});

	const usernameRef = useRef<HTMLInputElement>(null);
	const authStore = useAuthStore();
	const navigate = useNavigate();
	const mutation = useMutation({
		// 统一会话部署：服务端建立可撤销的身份会话（HttpOnly Cookie），浏览器不拿令牌；
		// 旧版部署：沿用平台 JWT。
		mutationFn: async (input: { username: string; password: string }) => {
			if (isCookieMode()) {
				await mutateSession((csrf) => client.service.webSession.login(input, csrf));
				return;
			}
			const data = await serviceApi.users.login(input);
			authStore.setToken(data.data!);
			authStore.setUsername(input.username);
		},
		onMutate: () => {
			banner.hideBanner();
			form.buttonMessage = "Signing in...";
			form.buttonDisabled = true;
		},
		onSuccess: () => {
			banner.showBanner("success", "Login success");
			form.buttonMessage = "Redirecting...";
			form.buttonDisabled = true;
			navigate({ to: "/service" });
		},
		onError: (error) => {
			banner.showErrorBanner(error, { 401: "用户名或密码错误" });
			form.buttonDisabled = false;
			form.buttonMessage = "Sign in";
			if (!isCookieMode()) authStore.removeToken();
		},
	});
	useEffect(() => {
		usernameRef.current?.focus();
	}, []);
	return (
		<div className="flex flex-col items-center justify-center pt-9 gap-5">
			<Avatar size={100} src="/float.png" />
			<Heading>Sign in to FloatCTF</Heading>
			<form
				onSubmit={(e) => {
					e.preventDefault();
					if (form.username === "" || form.password === "") {
						banner.showBanner("critical", "Username or password is empty");
						return;
					}
					mutation.mutate({
						username: form.username,
						password: form.password,
					});
				}}
				className="flex flex-col gap-2 w-full max-w-sm"
			>
				<FormControl required>
					<FormControl.Label>Username</FormControl.Label>
					<TextInput
						className="w-full"
						ref={usernameRef}
						name="username"
						autoComplete="username"
						placeholder="学号"
						value={form.username}
						onChange={(e) => {
							form.username = e.target.value;
						}}
					/>
				</FormControl>

				<FormControl required>
					<FormControl.Label>Password</FormControl.Label>
					<TextInput
						className="w-full"
						type="password"
						autoComplete="current-password"
						name="password"
						value={form.password}
						onChange={(e) => {
							form.password = e.target.value;
						}}
					/>
				</FormControl>

				<Button type="submit" variant="primary" disabled={form.buttonDisabled}>
					{form.buttonMessage}
				</Button>
				<div className="flex justify-between">
					<AppLink to="/register">Don't have an account? Register</AppLink>
					<AppLink to="/reset">Forgot password?</AppLink>
				</div>
			</form>

			<banner.BannerComponent />

			<Link href={getLearnOSUrl()} target="_blank" rel="noopener noreferrer">
				前往 LearnOS 学习平台 →
			</Link>
		</div>
	);
}
