<?php

namespace spec\PolyAuth\Caching;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use Stash\Driver\Apc;
use Stash\Pool;
use PolyAuth\Options;

class APCCacheSpec extends ObjectBehavior{

	public $prophet;

	function let(Pool $cache, Apc $driver, Options $options){
	
		$this->prophet = new Prophet;
		
		$mocks = [];
		$mocks += $this->setup_cache_mocks($cache);
		$mocks += $this->setup_options_mocks($options);
		
		$this->beConstructedWith(
			$mocks['cache'],
			$driver,
			$mocks['options']
		);
	
	}
	
	function setup_cache_mocks(Pool $cache){
	
		$cache->setDriver(Argument::any())->willReturn(true);
		
		$item = $this->prophet->prophesize('Stash\Item');
		$item->get()->willReturn('data');
		$item->set(Argument::cetera())->willReturn(true);
		$item->isMiss()->willReturn(true);
		$item->lock()->willReturn(true);
		$item->clear()->willReturn(true);
		$item = $item->reveal();
		
		$cache->getItem(Argument::any())->willReturn($item);
		$cache->purge()->willReturn(true);
		$cache->flush()->willReturn(true);
		
		return [
			'cache' => $cache,
		];
	
	}
	
	function setup_options_mocks(Options $options){
	
		//OPTIONS
		$options_array = $options->options;
		$options = $this->prophet->prophesize('PolyAuth\Options');
		$options->offsetGet(Argument::any())->will(function($args) use (&$options_array){
			$key = $args[0];
			return $options_array[$key];
		});
		$options->offsetSet(Argument::cetera())->will(function($args) use (&$options_array){
			if(is_null($args[0])){
				$options_array[] = $args[1];
			} else {
				$options_array[$args[0]] = $args[1];
			}
		});
		$options->offsetExists(Argument::any())->will(function($args) use (&$options_array){
			return isset($options_array[$args[0]]);
		});
		$options = $options->reveal();
		
		return [
			'options'	=> $options, 
		];
		
	}
	
	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\Caching\APCCache');
	}
	
	function it_should_get_cache_items(){
		$this->get('item')->shouldReturn('data');
	}
	
	function it_should_store_cache_items(){
		$this->set('item', 'data')->shouldReturn(true);
	}
	
	function it_should_check_if_items_exist(){
		//it shouldn't exist, if the isMiss is true!
		$this->exists('item')->shouldReturn(false);
	}
	
	function it_should_lock_items(){
		$this->lock('item')->shouldReturn(true);
	}
	
	function it_should_clear_items(){
		$this->clear('item')->shouldReturn(true);
	}
	
	function it_should_purge_items(){
		$this->purge()->shouldReturn(true);
	}
	
	function it_should_flush_cache(){
		$this->flush()->shouldReturn(true);
	}
	
}