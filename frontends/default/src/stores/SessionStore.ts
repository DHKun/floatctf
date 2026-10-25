import type { WebSessionStatus } from "@floatctf/sdk";
import { create } from "zustand";

/**
 * 主站统一 Cookie 会话的内存镜像（**不持久化**）。
 *
 * 登录态的唯一依据是服务端 `GET /api/users/web-session`；这里只缓存最近一次结果，
 * 刷新页面后重新向服务端读取。凭据是 HttpOnly Cookie，前端读不到也不保存。
 *
 * - `mode = "unknown"`：尚未向服务端确认（启动中）；
 * - `mode = "cookie"`：部署开启统一会话，`status` 有效；
 * - `mode = "legacy"`：部署未开启，继续使用 `AuthStore` 中的平台 JWT。
 */
type SessionState = {
	mode: "unknown" | "cookie" | "legacy";
	status: WebSessionStatus | null;
	setStatus: (status: WebSessionStatus) => void;
};

export const useSessionStore = create<SessionState>((set) => ({
	mode: "unknown",
	status: null,
	setStatus: (status) => set({ mode: status.mode, status }),
}));
