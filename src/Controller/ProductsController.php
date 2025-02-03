<?php

namespace App\Controller;

use App\Repository\ProductsRepository;
use App\Entity\Products;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductsController extends AbstractController
{
    #[Route('/products', name: 'products_list')]
    public function index(ProductsRepository $productRepository): Response
    {
        // Fetch all products from the database
        $products = $productRepository->findAll();

        return $this->render('products/index.html.twig', [
            'products' => $products,
        ]);
    }

    #[Route('/products/{slug}', name: 'products_details')]
    public function details(Products $product): Response
    {
        return $this->render('products/details.html.twig', compact('product'));
    }
}
