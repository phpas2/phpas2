<?php
/**
 * Copyright © 2019 PHPAS2. All rights reserved.
 */

namespace PHPAS2;

class DataObject
{
    /** @var array */
    protected $data=[];

    public function __call($name, $arguments)
    {
        $action = strtolower(substr($name, 0, 3));
        $varName = substr($name, 3);

        switch($action)
        {
            case 'get':
                return $this->getData($varName);
                break;

            case 'set':
                $this->setData($varName, $arguments[0]);
                break;

            case 'uns':
                $this->unsetData($varName);
                break;
        }

        return $this;
    }

    public function getData($var)
    {
        if (array_key_exists($var, $this->data)) {
            return $this->data[$var];
        }

        return null;
    }

    public function setData($var, $val=null)
    {
        $this->data[$var] = $val;
    }

    public function unsetData($var)
    {
        unset($this->data[$var]);
    }
}