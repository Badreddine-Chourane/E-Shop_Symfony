<?php

namespace App\Controller;

use App\Repository\CategoriesRepository;
use App\Repository\ProductsRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class MainController extends AbstractController
{
    #[Route('/', name: 'home')]
    public function index(CategoriesRepository $categoriesRepository, ProductsRepository $productsRepository): Response
    {
        // Fetch categories for the homepage
        $categories = $categoriesRepository->findBy([], ['categoryOrder' => 'asc']);

        // Fetch featured products or a subset of products for the homepage
        // Use 'id' to get the latest products (assuming 'id' is auto-incremented)
        $products = $productsRepository->findBy([], ['id' => 'desc'], 4); // Get 4 latest products

        return $this->render('main/index.html.twig', [
            'categories' => $categories,
            'products' => $products
        ]);
    }
}

