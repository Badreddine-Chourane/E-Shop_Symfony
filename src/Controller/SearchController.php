<?php

namespace App\Controller;

use App\Repository\ProductsRepository;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SearchController extends AbstractController
{
    #[Route('/search', name: 'search_products')]
    public function search(Request $request, ProductsRepository $productRepository): Response
    {
        $query = $request->query->get('query', '');

        // Fetch matching products from the database
        $products = $productRepository->createQueryBuilder('p')
            ->where('p.name LIKE :query')
            ->setParameter('query', '%' . $query . '%')
            ->getQuery()
            ->getResult();

        return $this->render('search/results.html.twig', [
            'products' => $products,
            'query' => $query,
        ]);
    }
}
