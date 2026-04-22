#!/usr/bin/env python
"""诊断脚本：测试 Agent 配置和连接"""

import sys
from app.config import get_settings
from app.agent_client import call_agent, AgentCallError

def test_config():
    """测试配置是否正确"""
    print("=" * 60)
    print("1. 检查配置...")
    print("=" * 60)
    
    settings = get_settings()
    
    print(f"✓ DASHSCOPE_API_KEY: {'已配置' if settings.dashscope_api_key else '❌ 未配置'}")
    print(f"✓ BAILIAN_APP_ID: {'已配置' if settings.bailian_app_id else '❌ 未配置'}")
    print(f"✓ BAILIAN_BASE_URL: {settings.bailian_base_url}")
    print(f"✓ BAILIAN_TIMEOUT: {settings.bailian_timeout}s")
    
    if not settings.dashscope_api_key or not settings.bailian_app_id:
        print("\n❌ 配置不完整，请检查 .env 文件")
        return False
    
    print("\n✓ 配置检查通过\n")
    return True

def test_agent_call():
    """测试 Agent 调用"""
    print("=" * 60)
    print("2. 测试 Agent 调用...")
    print("=" * 60)
    
    # 简单的测试 prompt
    test_prompt = "请用 JSON 格式回复：{\"status\": \"ok\", \"message\": \"测试成功\"}"
    
    try:
        print(f"发送测试请求...")
        result = call_agent(test_prompt)
        
        print(f"✓ 请求成功")
        print(f"  Request ID: {result.get('request_id', 'N/A')}")
        print(f"  Raw Text: {result.get('raw_text', '')[:100]}...")
        print(f"  Parsed: {result.get('parsed', {})}")
        
        return True
    except AgentCallError as e:
        print(f"❌ Agent 调用失败: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ 未知错误: {str(e)}")
        return False

def main():
    print("\n🔍 Magualine Agent 诊断工具\n")
    
    if not test_config():
        sys.exit(1)
    
    if not test_agent_call():
        print("\n💡 故障排查建议:")
        print("  1. 检查 API KEY 是否正确")
        print("  2. 检查网络连接")
        print("  3. 检查百炼服务是否可用")
        print("  4. 查看详细错误信息")
        sys.exit(1)
    
    print("\n✅ 所有检查通过！系统可以正常使用。\n")

if __name__ == "__main__":
    main()
