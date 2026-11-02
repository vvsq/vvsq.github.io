import type { BooknavGroup, BooknavPageConfig } from "../types/booknavConfig";

// 书签导航页面配置
export const booknavPageConfig: BooknavPageConfig = {
	// 页面标题，如果留空则使用 i18n 中的翻译
	title: "",

	// 页面描述文本，如果留空则使用 i18n 中的翻译
	description: "",

	// favicon 自动获取配置
	favicon: {
		// 书签未填写 icon 时，是否自动获取目标站点的 favicon 图标
		enabled: true,

		// favicon 接口地址，{domain} 为占位符，会被替换成目标站点域名
		// 更换接口只需保证地址里含有 {domain}，例如：
		//   https://a.favicon.im/{domain}
		//   https://favicon.im/{domain}
		api: "https://a.favicon.im/{domain}",
	},
};

// 书签导航配置
// 每个数组项是一个分类组，分类组内的 items 是该分类下的书签
export const booknavConfig: BooknavGroup[] = [
	{
		id: "re",
		name: "逆向与样本分析",
		icon: "material-symbols:bug-report-outline",
		desc: "逆向、脱壳与恶意样本分析的常用站点",
		weight: 100,
		items: [
			{
				title: "看雪论坛",
				url: "https://bbs.kanxue.com",
				desc: "国内最大的逆向工程与软件安全社区",
				// icon 可以填 astro-icon 图标名、图片 URL 或本地图片路径
				// 不填则通过上面的接口自动抓取目标站点 favicon
				weight: 10,
			},
			{
				title: "吾爱破解",
				url: "https://www.52pojie.cn",
				desc: "逆向与破解技术交流社区",
				weight: 9,
			},
			{
				title: "VirusTotal",
				url: "https://www.virustotal.com",
				desc: "多引擎在线查杀与样本情报",
				weight: 8,
			},
			{
				title: "微步在线",
				url: "https://x.threatbook.com",
				desc: "威胁情报查询与恶意样本分析",
				weight: 7,
			},
		],
	},
	{
		id: "ctf",
		name: "CTF",
		icon: "material-symbols:flag",
		desc: "赛事信息与练习平台",
		weight: 90,
		items: [
			{
				title: "CTFtime",
				url: "https://ctftime.org",
				desc: "全球 CTF 赛事日历与战队排名",
				weight: 10,
			},
			{
				title: "NSSCTF",
				url: "https://www.nssctf.cn",
				desc: "在线 CTF 练习平台",
				weight: 9,
			},
		],
	},
];
