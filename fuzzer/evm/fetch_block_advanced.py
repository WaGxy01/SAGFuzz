#!/usr/bin/env python3
"""
增强版区块获取工具
支持: 批量获取、自动重试、进度显示
"""

import pickle
import argparse
import time
from pathlib import Path
from typing import Optional, List
from web3 import Web3
from web3.exceptions import BlockNotFound


# 公共 RPC 节点列表 (作为备选)
PUBLIC_RPC_NODES = [
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://cloudflare-eth.com",
    "https://eth.merkle.io",
]


def get_web3_instance(rpc_url: Optional[str] = None, max_retries: int = 3) -> Web3:
    """
    创建 Web3 实例并验证连接
    """
    rpc_urls = [rpc_url] if rpc_url else PUBLIC_RPC_NODES
    
    for url in rpc_urls:
        print(f"尝试连接: {url}")
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={'timeout': 60}))
            if w3.is_connected():
                print(f"✓ 连接成功: {url}")
                print(f"  链 ID: {w3.eth.chain_id}")
                current_block = w3.eth.block_number
                print(f"  当前区块: {current_block}")
                return w3
        except Exception as e:
            print(f"✗ 连接失败: {e}")
            continue
    
    raise ConnectionError("无法连接到任何以太坊节点")


def fetch_block_with_retry(w3: Web3, block_number: int, max_retries: int = 3) -> dict:
    """
    带重试机制的区块获取
    """
    for attempt in range(max_retries):
        try:
            print(f"  尝试 {attempt + 1}/{max_retries}...")
            block = w3.eth.get_block(block_number, full_transactions=False)
            return block
        except BlockNotFound:
            raise BlockNotFound(f"区块 {block_number} 不存在")
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            print(f"  错误: {e}, 等待 5 秒后重试...")
            time.sleep(5)


def save_block(block: dict, output_file: str) -> None:
    """
    保存区块数据为 pickle 格式
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'wb') as f:
        pickle.dump(block, f)
    
    # 验证
    with open(output_path, 'rb') as f:
        loaded_block = pickle.load(f)
        assert loaded_block['number'] == block['number']


def display_block_info(block: dict) -> None:
    """
    显示区块信息
    """
    print(f"\n{'='*60}")
    print(f"区块 #{block['number']}")
    print(f"{'='*60}")
    print(f"哈希:       {block['hash'].hex()}")
    print(f"父哈希:     {block['parentHash'].hex()}")
    print(f"时间戳:     {block['timestamp']} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(block['timestamp']))})")
    print(f"矿工:       {block['miner']}")
    print(f"难度:       {block.get('difficulty', 'N/A')}")
    print(f"总难度:     {block.get('totalDifficulty', 'N/A')}")
    print(f"交易数:     {len(block['transactions'])}")
    print(f"Gas Used:   {block['gasUsed']:,} / {block['gasLimit']:,} ({block['gasUsed']/block['gasLimit']*100:.2f}%)")
    print(f"区块大小:   {block['size']:,} bytes")
    print(f"Nonce:      {block.get('nonce', 'N/A')}")
    print(f"Extra Data: {block.get('extraData', 'N/A')}")
    print(f"{'='*60}\n")


def fetch_block_range(w3: Web3, start_block: int, end_block: int, 
                      output_dir: str = "blocks") -> None:
    """
    批量获取区块
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    total = end_block - start_block + 1
    print(f"\n开始批量获取区块 {start_block} 到 {end_block} (共 {total} 个)")
    
    for i, block_num in enumerate(range(start_block, end_block + 1), 1):
        print(f"\n[{i}/{total}] 获取区块 {block_num}...")
        
        try:
            output_file = output_path / f"{block_num}.block"
            
            # 跳过已存在的文件
            if output_file.exists():
                print(f"  ✓ 已存在,跳过")
                continue
            
            # 获取区块
            block = fetch_block_with_retry(w3, block_num)
            
            # 保存
            save_block(block, str(output_file))
            print(f"  ✓ 已保存到 {output_file}")
            print(f"  交易数: {len(block['transactions'])}, Gas: {block['gasUsed']:,}")
            
            # 避免请求过快
            if i < total:
                time.sleep(0.5)
                
        except Exception as e:
            print(f"  ✗ 失败: {e}")
            continue


def main():
    parser = argparse.ArgumentParser(
        description='以太坊区块数据获取工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 获取单个区块
  python fetch_block_advanced.py --block 18200000 --output 18200000.block
  
  # 使用自定义 RPC
  python fetch_block_advanced.py --block 18200000 --output 18200000.block --rpc https://mainnet.infura.io/v3/YOUR_KEY
  
  # 批量获取区块
  python fetch_block_advanced.py --range 18200000 18200010 --output-dir blocks/
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--block', type=int, help='单个区块号')
    group.add_argument('--range', type=int, nargs=2, metavar=('START', 'END'),
                       help='区块范围 (包含)')
    
    parser.add_argument('--output', type=str, help='输出文件路径 (单个区块模式)')
    parser.add_argument('--output-dir', type=str, default='blocks',
                        help='输出目录 (批量模式, 默认: blocks/)')
    parser.add_argument('--rpc', type=str, help='以太坊 RPC URL')
    parser.add_argument('--retries', type=int, default=3, help='重试次数 (默认: 3)')
    
    args = parser.parse_args()
    
    try:
        # 连接到节点
        w3 = get_web3_instance(args.rpc, args.retries)
        
        # 单个区块模式
        if args.block:
            if not args.output:
                args.output = f"{args.block}.block"
            
            print(f"\n获取区块 #{args.block}...")
            block = fetch_block_with_retry(w3, args.block, args.retries)
            display_block_info(block)
            
            save_block(block, args.output)
            print(f"✓ 成功保存到: {args.output}")
        
        # 批量模式
        else:
            start, end = args.range
            if start > end:
                raise ValueError("起始区块号不能大于结束区块号")
            
            fetch_block_range(w3, start, end, args.output_dir)
            print(f"\n✓ 批量获取完成! 文件保存在: {args.output_dir}/")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
